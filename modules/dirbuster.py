import requests
import threading
import queue
import logging
import time
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class DirBuster:
    def __init__(self, target_url: str, wordlist_file: str = "wordlists/common2.txt", 
                 output_file: str = "report.txt", threads: int = 10, delay: float = 0.1):
        self.target_url = self.normalize_url(target_url)
        self.wordlist_file = wordlist_file
        self.output_file = output_file
        self.threads = threads
        self.delay = delay
        self.output_lock = threading.Lock()
        
    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure URL has proper scheme."""
        if not url.startswith(("http://", "https://")):
            return "http://" + url
        return url

    def load_wordlist(self) -> queue.Queue:
        """Load wordlist from file into queue."""
        q = queue.Queue()
        try:
            with open(self.wordlist_file, "r") as f:
                for line in f:
                    if directory := line.strip():
                        q.put(directory)
        except FileNotFoundError:
            logging.error(f"Wordlist file '{self.wordlist_file}' not found!")
            raise
        return q

    def worker(self, q: queue.Queue):
        """Check directories from the queue."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        
        while not q.empty():
            directory = q.get()
            test_url = f"{self.target_url.rstrip('/')}/{directory}/"
            
            try:
                time.sleep(self.delay)  # Rate limiting
                
                response = requests.get(test_url, headers=headers, timeout=5)
                
                if response.status_code in [200, 403]:
                    if response.status_code == 200:
                        logging.info(f"[✔] Found (200): {test_url}")
                        result = f"[✔] {test_url} [200]\n"
                    elif response.status_code == 403:
                        logging.info(f"[!] Forbidden (403): {test_url}")
                        result = f"[!] {test_url} [403]\n"
                    with self.output_lock:
                        with open(self.output_file, "a", encoding="utf-8") as f:
                            f.write(result)
                    print(f"Status {response.status_code}: {test_url}")
                else:
                    # Print progress info with checked count
                    with self.output_lock:
                        progress = f"Checked {self.checked_count+1}/{self.total_tasks} - {test_url} - Status: {response.status_code}"
                    print(progress, end='\r')
                    
            except requests.RequestException as e:
                logging.warning(f"[!] Error checking {test_url}: {e}")
            
            # Update checked counter and print progress
            with self.output_lock:
                self.checked_count += 1
                progress = f"Checked {self.checked_count}/{self.total_tasks}"
            print(progress, end='\r')
            
            q.task_done()

    def run(self):
        """Execute directory bruteforce scan."""
        with open(self.output_file, "w") as f:
            f.write(f"[+] Directory Bruteforce Report for {self.target_url}\n")
            f.write("=" * 50 + "\n")
        
        q = self.load_wordlist()
        self.total_tasks = q.qsize()         # new: store total tasks
        self.checked_count = 0               # new: initialize counter
        logging.info(f"[+] Starting with {self.threads} threads... Total tasks: {self.total_tasks}")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, args=(q,))
            t.start()
            threads.append(t)
        
        q.join()
        logging.info(f"[✔] Scan complete! Results in '{self.output_file}'")

def dirbuster_main(target_url: str):
    """Main function for standalone/cli use."""
    scanner = DirBuster(target_url)
    scanner.run()

def run_dirbuster(target_url: str, wordlist: Optional[str] = None, 
                 threads: Optional[int] = None) -> str:
    """
    Programmatic interface for directory bruteforce.
    
    Args:
        target_url: URL to scan
        wordlist: Path to custom wordlist
        threads: Number of threads to use
        
    Returns:
        Path to output file
    """
    scanner = DirBuster(
        target_url,
        wordlist_file=wordlist or "wordlists/common2.txt",
        threads=threads or 10
    )
    scanner.run()
    return scanner.output_file

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target website URL")
    parser.add_argument("-w", "--wordlist", default="wordlists/common2.txt")
    parser.add_argument("-t", "--threads", type=int, default=10)
    args = parser.parse_args()
    
    dirbuster_main(args.url)