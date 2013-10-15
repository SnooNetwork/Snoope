/* RequiredLibraries: ssl,crypto */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#define ROUNDS		(128000)
#define SALTLEN		(16)

#include "module.h"



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



class CommandNSHash : public Command
{
 public:
	CommandNSHash(Module *creator) : Command(creator, "nickserv/hash", 2, 2)
	{
		this->SetSyntax(_("\037password\037"));
		this->SetDesc(_("Hashes my example hash"));
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) anope_override
	{
		const Anope::string &src = params[0];
		Anope::string dest;
			const Anope::string &salt=params[1];
			Log(LOG_COMMAND) << "I got here";
			source.Reply(_("MEOW! Specially for you \002%s\002"));
			static char outbuf[289];
			static unsigned char digestbuf[SHA512_DIGEST_LENGTH];
			int res, iter;

			memcpy(outbuf, salt.c_str(), SALTLEN);
			res=PKCS5_PBKDF2_HMAC(src.c_str(),src.length(),(const unsigned char *)salt.c_str(),SALTLEN,ROUNDS,EVP_sha512(), SHA512_DIGEST_LENGTH, digestbuf);
			for (iter = 0; iter < SHA512_DIGEST_LENGTH; iter++)
			{
				sprintf(outbuf + SALTLEN + (iter * 2), "%02x", 255 & digestbuf[iter]);
			}
			for(int i=0;i<289;i++)
				Log(LOG_COMMAND) << "THis is the next char: " << outbuf[i];
			dest = Anope::string(outbuf);
			source.Reply(_(dest));
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) anope_override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Tests a password agaisnt the hash for nekosune"));
		return true;
	}
};

class NSHash : public Module
{
	CommandNSHash commandnshash;

 public:
	NSHash(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR),
		commandnshash(this)
	{

	}
};

MODULE_INIT(NSHash)
