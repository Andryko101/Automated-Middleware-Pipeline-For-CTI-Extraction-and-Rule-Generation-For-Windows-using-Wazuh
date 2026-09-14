import scrapy
import sqlite3
from cti_scraper.items import CtiArticleItem

class DfirSpider(scrapy.Spider):
    name = "dfir"
    allowed_domains = ["thedfirreport.com"]
    start_urls = ["https://thedfirreport.com/reports/"]

    def __init__(self, *args, **kwargs):
        super(DfirSpider, self).__init__(*args, **kwargs)
        # Initialize the database connection
        self.con = sqlite3.connect('seen_urls.db')
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def parse(self, response):
        # 1. Using your cleaner 'noHover' CSS selector
        article_links = response.css("a.noHover::attr(href)").getall()
        for link in article_links:
            # 2. Check if the URL has already been scraped
            self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (link,))
            if self.cur.fetchone() is None:
                yield response.follow(link, callback=self.parse_report)
            else:
                self.logger.info(f"Skipping previously scraped DFIR URL: {link}")

    def parse_report(self, response):
        title = response.css("h1.entry-title::text").get(default="").strip()

        # The DFIR report puts its dense technical data in paragraphs, preformatted blocks, and code blocks
        # We want to extract all of them to capture command lines and Sysmon logs
        content_blocks = response.css(".entry-content p::text,.content-column p::text, .entry-content pre::text, .entry-content code::text").getall()

        for block in content_blocks:
            cleaned_text = block.strip()
            
            # Filter out short spacing artifacts, but keep it low enough to catch command lines
            if len(cleaned_text) > 20:
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = cleaned_text
                yield item

    def closed(self, reason):
        # Cleanly close the database connection
        self.con.close()