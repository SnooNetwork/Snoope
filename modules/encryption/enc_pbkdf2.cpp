/* RequiredLibraries: ssl,crypto */
#include "module.h"
#include "encryption.h"
//#include "ssl.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#define ROUNDS		(128000)
#define SALTLEN		(16)

static const char alphanum[] =
"0123456789"
"!@#$%^&*"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz";

int stringLength = sizeof(alphanum) - 1;

char genRandom()  // Random string generator function.
{

    return alphanum[rand() % stringLength];
}

char* random_string(int len)
{
	srand(time(0));
	char* ran;
	memset(ran,0,len+1);
	for(int i=0;i<len;i++)
	{
		ran[i]=genRandom();
	}
	ran[len]='\0';
	return ran;
}
inline static  char*  pbkdf2_salt(void)
{
	static char buf[SALTLEN + 1];
	char* randstr=random_string(SALTLEN);
	strcpy(buf,randstr);
	free(randstr);
	return buf;
}
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
			   const unsigned char *salt, int saltlen, int iter,
			   const EVP_MD *digest,
			   int keylen, unsigned char *out)
{
	unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
	int cplen, j, k, tkeylen, mdlen;
	unsigned long i = 1;
	HMAC_CTX hctx;

	mdlen = EVP_MD_size(digest);

	HMAC_CTX_init(&hctx);
	p = out;
	tkeylen = keylen;
	if(!pass)
		passlen = 0;
	else if(passlen == -1)
		passlen = strlen(pass);
	while(tkeylen)
	{
		if(tkeylen > mdlen)
			cplen = mdlen;
		else
			cplen = tkeylen;
		/* We are unlikely to ever use more than 256 blocks (5120 bits!)
		 * but just in case...
		 */
		itmp[0] = (unsigned char)((i >> 24) & 0xff);
		itmp[1] = (unsigned char)((i >> 16) & 0xff);
		itmp[2] = (unsigned char)((i >> 8) & 0xff);
		itmp[3] = (unsigned char)(i & 0xff);
		HMAC_Init_ex(&hctx, pass, passlen, digest, NULL);
		HMAC_Update(&hctx, salt, saltlen);
		HMAC_Update(&hctx, itmp, 4);
		HMAC_Final(&hctx, digtmp, NULL);
		memcpy(p, digtmp, cplen);
		for(j = 1; j < iter; j++)
		{
			HMAC(digest, pass, passlen,
				 digtmp, mdlen, digtmp, NULL);
			for(k = 0; k < cplen; k++)
				p[k] ^= digtmp[k];
		}
		tkeylen-= cplen;
		i++;
		p+= cplen;
	}
	HMAC_CTX_cleanup(&hctx);
	return 1;
}
class EPBKDF2 : public Module
{
	char*  salt;
	
	public:
		EPBKDF2(const Anope::string &modname,const Anope::string &creator) : Module(modname,creator,ENCRYPTION| VENDOR)
		{
		}
		
		int GetSaltFromPass(const Anope::string &password)
		{
			size_t pos = password.find(':');
			if(pos== Anope::string::npos)
				return -1;
			Anope::string buf = password.substr(password.find(':', pos + 1) + 1, password.length());
			memcpy(salt,buf.c_str(),SALTLEN);
			return 1;
		}
		EventReturn OnEncrypt(const Anope::string &src, Anope::string &dest) anope_override
		{
			static char outbuf[289];
			
			static unsigned char digestbuf[SHA512_DIGEST_LENGTH];
			int res, iter;
	
			//memcpy(outbuf, src.c_str(), SALTLEN);
			res=PKCS5_PBKDF2_HMAC(src.c_str(),src.length(),(const unsigned char *)salt,SALTLEN,ROUNDS,EVP_sha512(), SHA512_DIGEST_LENGTH, digestbuf);
			for (iter = 0; iter < SHA512_DIGEST_LENGTH; iter++)
			{
//				Log(LOG_COMMAND) << "This is a test " << digestbuf[iter];
				sprintf(outbuf +  (iter * 2), "%02x", 255 & digestbuf[iter]);
			}
			dest = Anope::string("pbkdf2:")+Anope::string(outbuf)+Anope::string(":")+Anope::string(salt);
			Log(LOG_COMMAND) << "(enc_pbkd2) hashed password from [" << src << "] to [" << dest << "]";
			return EVENT_ALLOW;
		}

		void OnCheckAuthentication(User *, IdentifyRequest *req) anope_override
		{
			const NickAlias *na = NickAlias::Find(req->GetAccount());
			if (na == NULL)
				return;
			NickCore *nc = na->nc;
	
			size_t pos = nc->pass.find(':');
			if (pos == Anope::string::npos)
				return;
			Anope::string hash_method(nc->pass.begin(), nc->pass.begin() + pos);
			if (!hash_method.equals_cs("pbkdf2"))
				return;
			Anope::string buf;
			if(GetSaltFromPass(nc->pass)==-1)
			{
				salt=pbkdf2_salt();
			}
		this->OnEncrypt(req->GetPassword(), buf);
		if (nc->pass.equals_cs(buf))
		{
			/* if we are NOT the first module in the list,
			 * we want to re-encrypt the pass with the new encryption
			 */
			if (ModuleManager::FindFirstOf(ENCRYPTION) != this)
				Anope::Encrypt(req->GetPassword(), nc->pass);
			req->Success(this);
		}
	}
};
MODULE_INIT(EPBKDF2)

