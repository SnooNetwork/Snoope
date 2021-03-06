#ifndef OS_NEWS
#define OS_NEWS

enum NewsType
{
	NEWS_LOGON,
	NEWS_RANDOM,
	NEWS_OPER
};

struct NewsMessages
{
	NewsType type;
	Anope::string name;
	const char *msgs[10];
};

struct NewsItem : Serializable
{
	NewsType type;
	Anope::string text;
	Anope::string who;
	time_t time;

	NewsItem() : Serializable("NewsItem") { }
	void Serialize(Serialize::Data &data) const anope_override;
	static Serializable* Unserialize(Serializable *obj, Serialize::Data &data);
};

class NewsService : public Service
{
 public:
	NewsService(Module *m) : Service(m, "NewsService", "news") { }
	
	virtual void AddNewsItem(NewsItem *n) = 0;
	
	virtual void DelNewsItem(NewsItem *n) = 0;
	
	virtual std::vector<NewsItem *> &GetNewsList(NewsType t) = 0;
};

static ServiceReference<NewsService> news_service("NewsService", "news");

void NewsItem::Serialize(Serialize::Data &data) const
{
	data["type"] << this->type;
	data["text"] << this->text;
	data["who"] << this->who;
	data["time"] << this->time;
}

Serializable* NewsItem::Unserialize(Serializable *obj, Serialize::Data &data)
{
	if (!news_service)
		return NULL;

	NewsItem *ni;
	if (obj)
		ni = anope_dynamic_static_cast<NewsItem *>(obj);
	else
		ni = new NewsItem();

	unsigned int t;
	data["type"] >> t;
	ni->type = static_cast<NewsType>(t);
	data["text"] >> ni->text;
	data["who"] >> ni->who;
	data["time"] >> ni->time;

	if (!obj)
		news_service->AddNewsItem(ni);
	return ni;
}

#endif // OS_NEWS

