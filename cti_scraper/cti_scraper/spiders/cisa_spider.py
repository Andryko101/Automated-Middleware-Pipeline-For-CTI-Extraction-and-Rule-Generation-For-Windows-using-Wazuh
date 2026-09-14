import scrapy
import sqlite3
from cti_scraper.items import CtiArticleItem

class CisaSpider(scrapy.Spider):
    name = "cisa"
    allowed_domains = ["cisa.gov"]
    start_urls = ["https://www.cisa.gov/news-events/cybersecurity-advisories"]

    # Add this block to bypass the WAF
    custom_settings = {
        'ROBOTSTXT_OBEY': False,
        'DEFAULT_REQUEST_HEADERS': {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
        }
    }

    def __init__(self, *args, **kwargs):
        super(CisaSpider, self).__init__(*args, **kwargs)
        self.con = sqlite3.connect('seen_urls.db')
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def parse(self, response):
        # Extract article links
        article_links = response.css("div.c-teaser__content h3 a::attr(href)").getall()
        
        for link in article_links:
            # Resolve relative URLs to absolute before checking the database
            absolute_url = response.urljoin(link)
            
            self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (absolute_url,))
            if self.cur.fetchone() is None:
                yield scrapy.Request(absolute_url, callback=self.parse_report)
            else:
                self.logger.info(f"Skipping previously scraped CISA URL: {absolute_url}")

        # Handle Pagination
        next_page = response.css("a.b-pagination__link--next::attr(href)").get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_report(self, response):
        title = response.css("h1::text, title::text").get(default="").strip()
        
        # Select the containers themselves, not the raw text nodes
        containers = response.css("main p, main li, article p, article li")

        for container in containers:
            # xpath('string(.)') joins all nested text inside the container into one sentence
            full_text = container.xpath("string(.)").get(default="").strip()
            
            if len(full_text) > 20:
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = full_text
                yield item

    def closed(self, reason):
        self.con.close()