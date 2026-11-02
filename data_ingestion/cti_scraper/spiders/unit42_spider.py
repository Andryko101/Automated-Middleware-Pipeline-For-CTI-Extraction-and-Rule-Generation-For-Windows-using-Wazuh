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

    def is_windows_telemetry(self, text):
        """Checks if the text contains high-fidelity Windows telemetry keywords."""
        windows_keywords = [
            'powershell', 'cmd.exe', '.exe', 'sysmon', 'registry', 
            'winlogon', 'schtasks', 'net.exe', 'vssadmin', 'wmic', 
            'event id', 'services.exe', 'lsass.exe', 'explorer.exe'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in windows_keywords)

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
        title = response.css("h1.entry-title::text").get(default="").strip()
        content_blocks = response.css(".entry-content p::text,.content-column p::text, .entry-content pre::text, .entry-content code::text").getall()

        for block in content_blocks:
            cleaned_text = block.strip()
            
            # 1. Length check
            if len(cleaned_text) > 20:
                # 2. Windows Telemetry Filter Check
                if self.is_windows_telemetry(cleaned_text):
                    item = CtiArticleItem()
                    item["title"] = title
                    item["source_url"] = response.url
                    item["text"] = cleaned_text
                    yield item
                else:
                    self.logger.debug(f"Dropping non-Windows text block: {cleaned_text[:30]}...")

    def closed(self, reason):
        self.con.close()