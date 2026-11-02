import scrapy
import re
import sqlite3

class CisaTacticalSpider(scrapy.Spider):
    name = "cisa_tactical"
    start_urls = ['https://www.cisa.gov/news-events/cybersecurity-advisories']

    custom_settings = {
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
        
        if target_url:
            self.start_urls = [target_url]
        else:
            self.start_urls = ['https://www.cisa.gov/news-events/cybersecurity-advisories']
            
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
        links = response.css('a::attr(href)').getall()
        
        for link in links:
            if re.search(r'aa\d{2}-\d{3}', link.lower()) and '/alerts/' not in link.lower():
                self.cur.execute("SELECT url FROM seen_urls WHERE url = ?", (response.urljoin(link),))
                if self.cur.fetchone() is None:
                    yield response.follow(link, callback=self.parse_advisory)
                else:
                    self.logger.info(f"Skipping previously scraped CISA URL: {link}")

        next_page = response.css('a[rel="next"]::attr(href), li.pager__item--next a::attr(href)').get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_advisory(self, response):
        title = response.css('h1::text').get(default='').strip()
        elements = response.xpath('//main//p | //main//li')
        
        for el in elements:
            text = " ".join(el.xpath('.//text()').getall())
            text = " ".join(text.split()).strip()
            
            # Length check AND Windows telemetry keyword check
            if len(text) > 20:
                if self.is_windows_telemetry(text):
                    yield {
                        'title': title,
                        'source_url': response.url,
                        'text': text
                    }
                else:
                    self.logger.debug(f"Dropping non-Windows text block: {text[:30]}...")

    def closed(self, reason):
        self.con.close()