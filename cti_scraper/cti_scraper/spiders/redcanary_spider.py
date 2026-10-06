import scrapy
import sqlite3
from cti_scraper.items import CtiArticleItem

class RedCanarySpider(scrapy.Spider):
    name = "redcanary"
    allowed_domains = ["redcanary.com"]
    # Target the XML RSS feed directly
    start_urls = ["https://redcanary.com/feed/"]

    def __init__(self, *args, **kwargs):
        super(RedCanarySpider, self).__init__(*args, **kwargs)
        self.con = sqlite3.connect('seen_urls.db')
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def parse(self, response):
        # Remove namespaces for clean XPath selection
        response.selector.remove_namespaces()
        article_links = response.xpath("//item/link/text()").getall()

        for link in article_links:
            # Database check for deduplication
            self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (link,))
            if self.cur.fetchone() is None:
                yield response.follow(link, callback=self.parse_report)
            else:
                self.logger.info(f"Skipping previously scraped Red Canary URL: {link}")

    def parse_report(self, response):
        title = response.css("h1::text, title::text").get(default="").strip()
        
        # Cast a wide net for paragraphs, lists, and critical code blocks
        containers = response.css(
            "article p, article li, article pre, article code, "
            "main p, main li, main pre, main code, "
            ".post p, .post pre, .post code, "
            ".content p, .content pre, .content code"
        )

        for container in containers:
            full_text = container.xpath("string(.)").get(default="").strip()
            
            # Dropped to 10 characters to ensure we capture short command-line flags
            if len(full_text) > 10:
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = full_text
                yield item

    def closed(self, reason):
        self.con.close()