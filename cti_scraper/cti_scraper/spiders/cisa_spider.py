import scrapy
import re

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

    def parse(self, response):
        # Extract all links on the page
        links = response.css('a::attr(href)').getall()
        
        for link in links:
            # Match the standard CISA advisory format (e.g., aa24-123a)
            if re.search(r'aa\d{2}-\d{3}', link.lower()) and '/alerts/' not in link.lower():
                yield response.follow(link, callback=self.parse_advisory)

        # Resilient pagination: Target the 'rel' attribute or the standard Drupal pagination class
        next_page = response.css('a[rel="next"]::attr(href), li.pager__item--next a::attr(href)').get()
        
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_advisory(self, response):
        title = response.css('h1::text').get(default='').strip()
        
        # Broadly target all paragraphs and list items inside the main content area
        elements = response.xpath('//main//p | //main//li')
        
        for el in elements:
            # Join all nested text nodes (handles <code>, <b>, <a> tags natively)
            # and clean up excess whitespace
            text = " ".join(el.xpath('.//text()').getall())
            text = " ".join(text.split()).strip()
            
            # Only yield meaningful sentences, discarding UI fragments
            if len(text) > 20:
                yield {
                    'title': title,
                    'source_url': response.url,
                    'text': text
                }