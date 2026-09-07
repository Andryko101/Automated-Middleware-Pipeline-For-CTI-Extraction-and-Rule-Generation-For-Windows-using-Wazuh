import scrapy
from cti_scraper.items import CtiArticleItem

class CisaSpider(scrapy.Spider):
    name = "cisa"
    allowed_domains = ["cisa.gov"]
    start_urls = [
        "https://www.cisa.gov/news-events/cybersecurity-advisories"
    ]

    def parse(self, response):
        # Broadened selector to catch links within article teasers or lists
        # Many modern Drupal/CMS sites use 'article' tags or classes containing 'teaser'
        advisory_links = response.css("article a::attr(href), .c-teaser a::attr(href)").getall()
        
        # Filter for links that look like advisories or alerts to avoid scraping unrelated pages
        for link in advisory_links:
             if "/news-events/cybersecurity-advisories/" in link or "/news-events/alerts/" in link:
                 yield response.follow(link, callback=self.parse_advisory)

        # Basic pagination check (often uses 'next' in the class or rel attribute)
        next_page = response.css("a[rel='next']::attr(href), .pager__item--next a::attr(href)").get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_advisory(self, response):
        # Attempt to grab the main heading
        title = response.css("h1::text").get(default="").strip()

        # Target all paragraph text within the main content area.
        # We look inside elements typically used for the main body to avoid nav/footer text.
        paragraphs = response.css("main p::text, .l-main p::text, article p::text").getall()

        for p in paragraphs:
            cleaned_text = p.strip()
            
            # Filter out short or boilerplate lines (disclaimers, headers)
            # We want substantive narrative sentences (e.g., > 60 characters)
            if len(cleaned_text) > 60:
                item = CtiArticleItem()
                item["title"] = title
                item["source_url"] = response.url
                item["text"] = cleaned_text
                yield item