import scrapy
import sqlite3
from cti_scraper.items import CtiArticleItem

class Unit42Spider(scrapy.Spider):
    name = "unit42"
    allowed_domains = ["unit42.paloaltonetworks.com"]
    # Target the XML feed!
    start_urls = ["https://unit42.paloaltonetworks.com/feed/"]

    def __init__(self, *args, **kwargs):
        super(Unit42Spider, self).__init__(*args, **kwargs)
        self.con = sqlite3.connect('seen_urls.db')
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def parse(self, response):
        response.selector.remove_namespaces()
        article_links = response.xpath("//item/link/text()").getall()

        for link in article_links:
            self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (link,))
            if self.cur.fetchone() is None:
                yield response.follow(link, callback=self.parse_report)
            else:
                self.logger.info(f"Skipping previously scraped Unit 42 URL: {link}")

    def parse_report(self, response):
        title = response.css("h1::text, title::text").get(default="").strip()
        
        # Cast a wide net for standard blog text containers
        containers = response.css(
            "main p, main li, "
            "article p, article li, "
            ".post-content p, .post-content li, "
            ".entry-content p, .entry-content li, "
            ".rich-text p, .rich-text li"
        )

        for container in containers:
            full_text = container.xpath("string(.)").get(default="").strip()
            
            # 20 chars helps filter out short navigation or social sharing buttons
            if len(full_text) > 20:
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = full_text
                yield item

    def closed(self, reason):
        self.con.close()