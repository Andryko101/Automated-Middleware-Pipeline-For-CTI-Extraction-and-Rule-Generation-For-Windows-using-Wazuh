# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html
import re
import sqlite3
from scrapy.exceptions import DropItem
# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
from cti_scraper.settings import SEEN_URLS_DB


class CtiScraperPipeline:
    def process_item(self, item):
        return item

class WindowsFilterPipeline:
    def __init__(self):
        self.windows_keywords = [
            ".exe", ".dll", ".ps1", ".bat", ".vbs", "powershell", "cmd.exe",
            "sysmon", "registry", "hklm", "hkcu", "c:\\", "system32",
            "appdata", "wmi", "svchost", "rundll32", "regsvr32"
        ]
        # Keep platform-agnostic IOCs (defanged domains/URLs, IPv4s, SHA-256 hashes)
        self.ioc_pattern = re.compile(
            r'(\[\.\]|\[:\]|hxxps?://|'
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b|'
            r'\b[a-fA-F0-9]{64}\b)',
            re.IGNORECASE
        )

    def process_item(self, item, spider):
        text = item.get("text", "")
        text_lower = text.lower()

        if any(kw in text_lower for kw in self.windows_keywords) or self.ioc_pattern.search(text):
            return item

        raise DropItem("Non-telemetry / non-IOC prose detected")

class SeenURLPipeline:
    def __init__(self):
        self.con = sqlite3.connect(SEEN_URLS_DB)
        self.cur = self.con.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS seen_urls(
                url TEXT PRIMARY KEY
            )
        """)
        self.con.commit()

    def process_item(self, item, spider):
        adapter = ItemAdapter(item)
        url = adapter.get('source_url')
        
        # Use INSERT OR IGNORE to silently skip duplicate URLs from the same article
        self.cur.execute("INSERT OR IGNORE INTO seen_urls (url) VALUES (?)", (url,))
        self.con.commit()
        
        # Always return the item so it gets written to your JSON file
        return item

    def close_spider(self, spider):
        self.con.close()