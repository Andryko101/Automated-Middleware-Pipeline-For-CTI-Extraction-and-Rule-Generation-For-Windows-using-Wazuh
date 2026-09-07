# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

from dataclasses import dataclass


@dataclass
class CtiScraperItem:
    # define the fields for your item here like:
    # name: str | None = None
    pass

import scrapy

class CtiArticleItem(scrapy.Item):
    title = scrapy.Field()
    source_url = scrapy.Field()
    text = scrapy.Field()