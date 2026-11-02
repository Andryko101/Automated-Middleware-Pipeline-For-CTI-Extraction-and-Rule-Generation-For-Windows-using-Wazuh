import os
import sqlite3
import google_reader
from google_reader import Client
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

# Import your 4 spiders
from cti_scraper.spiders.cisa_spider import CisaTacticalSpider
from cti_scraper.spiders.dfir_scraper import DfirSpider
from cti_scraper.spiders.redcanary_spider import RedCanarySpider
from cti_scraper.spiders.unit42_spider import Unit42Spider

FRESHRSS_URL = "https://cti-freshrss.onrender.com/api/greader.php/"
USERNAME = "andrew"
API_PASSWORD = "freshrss"

def get_spider_class(url):
    """Maps an incoming RSS article URL to the correct Scrapy spider."""
    if "cisa.gov" in url:
        return CisaTacticalSpider
    elif "thedfirreport.com" in url:
        return DfirSpider
    elif "redcanary.com" in url:
        return RedCanarySpider
    elif "unit42.paloaltonetworks.com" in url:
        return Unit42Spider
    return None

def run_pipeline_for_feed():
    print("Connecting to FreshRSS on Render...")
    client = Client(FRESHRSS_URL)
    
    try:
        auth_token = client.login(USERNAME, API_PASSWORD)
        csrf_token = client.get_token(auth_token)
    except Exception as e:
        print(f"Authentication failed: {e}")
        return

    # Fetch unread items from FreshRSS reading list
    try:
        unread_stream = client.get_stream_items_ids(auth_token, stream_id="user/-/state/com.google/reading-list", limit=10)
        if not unread_stream or not unread_stream.item_refs:
            print("No new unread threat intel articles found in FreshRSS.")
            return

        item_ids = [ref.id for ref in unread_stream.item_refs]
        response_data = client.get_stream_items_contents(auth_token, csrf_token, item_ids=item_ids)
        items_detail = response_data.items if hasattr(response_data, 'items') else response_data
        
        # Connect to local seen_urls.db for fallback deduplication
        con = sqlite3.connect('seen_urls.db')
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS seen_urls(url TEXT PRIMARY KEY)")
        
        process = CrawlerProcess(get_project_settings())
        processed_item_ids = []

        for item in items_detail:
            title = getattr(item, 'title', 'No Title')
            
            # Robustly extract the real article URL from alternate links or attributes
            article_url = None
            if hasattr(item, 'url') and item.url:
                article_url = item.url
            elif hasattr(item, 'alternate') and item.alternate:
                # alternate is usually a list of dicts or objects containing 'href'
                alt = item.alternate[0]
                article_url = alt.get('href') if isinstance(alt, dict) else getattr(alt, 'href', None)
            elif hasattr(item, 'canonical') and item.canonical:
                can = item.canonical[0]
                article_url = can.get('href') if isinstance(can, dict) else getattr(can, 'href', None)
            
            # Fallback check if URL is buried anywhere else
            if not article_url:
                # Look through any attribute string for an http link
                for attr_val in item.__dict__.values():
                    if isinstance(attr_val, str) and attr_val.startswith('http'):
                        article_url = attr_val
                        break

            if not article_url or "google.com" in article_url:
                print(f"Skipping item with invalid/missing target URL: {title}")
                continue

            # Check local DB
            cur.execute("SELECT url FROM seen_urls WHERE url = ?", (article_url,))
            if cur.fetchone() is not None:
                print(f"Skipping already seen URL: {article_url}")
                continue

            spider_class = get_spider_class(article_url)
            if spider_class:
                print(f"\n[FreshRSS Trigger] Dispatching {spider_class.name} for: {title}")
                print(f"Target URL: {article_url}")
                
                process.crawl(spider_class, target_url=article_url)
                processed_item_ids.append(item.id)
            else:
                print(f"No matching spider found for URL: {article_url}")

        con.close()

        # Execute all queued Scrapy spiders sequentially/concurrently in this process
        process.start() 

        # Mark processed items as 'read' in FreshRSS so they don't refetch
        if processed_item_ids:
            client.edit_tags(auth_token, csrf_token, item_ids=processed_item_ids, add_tags=["user/-/state/com.google/read"])
            print("\nSuccessfully processed batch and marked items as read in FreshRSS.")

    except Exception as e:
        print(f"Error during FreshRSS sync: {e}")

if __name__ == "__main__":
    run_pipeline_for_feed()