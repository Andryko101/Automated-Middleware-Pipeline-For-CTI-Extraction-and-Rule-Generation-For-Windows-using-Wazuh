import scrapy
import re
import sqlite3
from cti_scraper.items import CtiArticleItem
from cti_scraper.settings import SEEN_URLS_DB


class CisaTacticalSpider(scrapy.Spider):
    name = "cisa_tactical"
    allowed_domains = ["cisa.gov"]
    start_urls = ['https://www.cisa.gov/news-events/cybersecurity-advisories']

    custom_settings = {
        # CISA advisories are public-domain defensive intel; WAF/robots rules block default
    # Scrapy user-agents, so we scope ROBOTSTXT_OBEY=False strictly to cisa.gov with a 2s delay.
        'ROBOTSTXT_OBEY': False,
        'DEFAULT_REQUEST_HEADERS': {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Not A(Brand";v="99", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        },
        'DOWNLOAD_DELAY': 2.0,
    }

    def __init__(self, target_url=None, *args, **kwargs):
        super(CisaTacticalSpider, self).__init__(*args, **kwargs)
        self.target_url = target_url

        self.con = sqlite3.connect(SEEN_URLS_DB)
        self.cur = self.con.cursor()
        self.cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        self.con.commit()

    def start_requests(self):
        if self.target_url:
            yield scrapy.Request(self.target_url, callback=self.parse_advisory)
        else:
            for url in self.start_urls:
                yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        links = response.css('a::attr(href)').getall()

        for link in links:
            if re.search(r'aa\d{2}-\d{3}', link.lower()) and '/alerts/' not in link.lower():
                full_url = response.urljoin(link)
                self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (full_url,))
                if self.cur.fetchone() is None:
                    yield response.follow(link, callback=self.parse_advisory)
                else:
                    self.logger.info(f"Skipping previously scraped CISA URL: {link}")

        next_page = response.css('a[rel="next"]::attr(href), li.pager__item--next a::attr(href)').get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_advisory(self, response):
        title = (
            response.xpath('string((//main//h1)[1])').get(default='').strip()
            or response.xpath('string(//title)').get(default='').split('|')[0].strip()
        )
        # Include //main//td and //main//pre to capture CISA IOC tables and command blocks
        elements = response.xpath('//main//p | //main//li | //main//td | //main//pre')

        seen_blocks = set()
        for el in elements:
            text = " ".join(el.xpath('string(.)').get(default='').split()).strip()

            if len(text) > 10 and text not in seen_blocks:
                seen_blocks.add(text)
                item = CtiArticleItem()
                item['title'] = title
                item['source_url'] = response.url
                item['text'] = text
                yield item

    def closed(self, reason):
        self.con.close()