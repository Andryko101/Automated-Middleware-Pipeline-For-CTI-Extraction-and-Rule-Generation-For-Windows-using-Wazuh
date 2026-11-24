import scrapy
import sqlite3
from cti_scraper.items import CtiArticleItem
from cti_scraper.settings import SEEN_URLS_DB

class RedCanarySpider(scrapy.Spider):
    name = "redcanary"
    allowed_domains = ["redcanary.com", "zscaler.com"]
    start_urls = ["https://redcanary.com/feed/"]

    def __init__(self, target_url=None, *args, **kwargs):
        super(RedCanarySpider, self).__init__(*args, **kwargs)
        self.target_url = target_url

        self.con = sqlite3.connect(SEEN_URLS_DB)
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def start_requests(self):
        if self.target_url:
            yield scrapy.Request(self.target_url, callback=self.parse_report)
        else:
            for url in self.start_urls:
                yield scrapy.Request(url, callback=self.parse)


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
        title = response.xpath("string(//h1[1])").get(default="").strip()
        containers = response.css(
            "article p, article pre, article li, "
            "main p, main pre, main li, "
            ".entry-content p, .content-column p"
        )

        seen_blocks = set()
        for container in containers:
            full_text = " ".join(container.xpath("string(.)").get(default="").split())

            if len(full_text) > 20 and full_text not in seen_blocks:
                seen_blocks.add(full_text)
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = full_text
                yield item

    def closed(self, reason):
        self.con.close()