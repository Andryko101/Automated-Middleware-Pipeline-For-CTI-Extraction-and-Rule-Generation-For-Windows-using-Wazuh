# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html
import sqlite3
from scrapy.exceptions import DropItem
# useful for handling different item types with a single interface
from itemadapter import ItemAdapter


class CtiScraperPipeline:
    def process_item(self, item):
        return item

class WindowsFilterPipeline:
    def __init__(self):
        # High-fidelity strings that strongly indicate Windows telemetry
        self.windows_keywords = [
            ".exe", "powershell", "cmd.exe", "sysmon", "registry", 
            "hklm", "hkcu", "c:\\", "system32", "appdata", "wmi", "svchost"
        ]

    def process_item(self, item, spider):
        text_lower = item.get("text", "").lower()
        
        if any(keyword in text_lower for keyword in self.windows_keywords):
            return item
        else:
            raise DropItem("Non-Windows telemetry detected")

class SeenURLPipeline:
    def __init__(self):
        self.con = sqlite3.connect('seen_urls.db')
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