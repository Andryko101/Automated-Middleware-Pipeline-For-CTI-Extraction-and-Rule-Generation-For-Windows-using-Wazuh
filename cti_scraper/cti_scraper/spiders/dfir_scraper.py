import scrapy
from cti_scraper.items import CtiArticleItem

class DfirSpider(scrapy.Spider):
    name = "dfir"
    allowed_domains = ["thedfirreport.com"]
    start_urls = ["https://thedfirreport.com/reports/"]

    def parse(self, response):
        # 1. Using your cleaner 'nohover' CSS selector
        article_links = response.css("a.noHover::attr(href)").getall()
        for link in article_links:
            yield response.follow(link, callback=self.parse_report)


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