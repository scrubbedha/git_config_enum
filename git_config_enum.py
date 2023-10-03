import aiohttp
import asyncio
import csv
import ssl
import argparse
import logging
from tqdm import tqdm
from aiohttp_socks import ProxyConnector

# Ignore SSL errors for HTTPS requests
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


async def check_git_config(url, session):
    try:
        async with session.get(url, ssl=ssl_context, timeout=10) as response:
            if response.status == 200:
                content = await response.text()
                return content.startswith("[core]")
    except asyncio.TimeoutError:
        return False
    except aiohttp.ClientError as e:
        logging.error(f"Error occurred while making HTTP request: {e}")
        return False


async def process_domain(domain, proxy, user_agent):
    try:
        headers = {
            'User-Agent': user_agent
        }

        connector = None
        if proxy:
            connector = ProxyConnector.from_url(proxy)

        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            async with session.get(f'http://{domain}/.git/config', ssl=ssl_context, timeout=10) as http_response:
                async with session.get(f'https://{domain}/.git/config', ssl=ssl_context, timeout=10) as https_response:
                    http_result = await check_git_config(f'http://{domain}/.git/config', session)
                    https_result = await check_git_config(f'https://{domain}/.git/config', session)

        if http_result or https_result:
            print(f"{domain} has a valid .git/config")
    except Exception as e:
        logging.error(f"An exception occurred while processing domain {domain}: {e}")


async def main(csv_file, proxy, user_agent):
    # Limit the number of concurrent requests
    sem = asyncio.Semaphore(50)

    async def process_domain_with_limit(domain):
        async with sem:
            await process_domain(domain, proxy, user_agent)

    tasks = []

    logging.basicConfig(level=logging.ERROR)  # Configure appropriate logging level as needed

    with open(csv_file, newline="") as csvfile:
        csv_reader = csv.reader(csvfile)
        domains = [row[0] for row in csv_reader]

    with tqdm(total=len(domains), desc="Processing Domains") as pbar:
        for domain in domains:
            task = asyncio.ensure_future(process_domain_with_limit(domain))
            task.add_done_callback(lambda p, domain=domain: pbar.set_postfix({"Domain": domain}))
            tasks.append(task)

        await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Git config file enumeration")
    parser.add_argument("-f", "--file", help="Path to the CSV file containing target domain names", required=True)
    parser.add_argument("-x", "--proxy", help="SOCKS Proxy URL")
    args = parser.parse_args()

    file_arg = args.file
    proxy_arg = args.proxy

    print(f"File argument: {file_arg}")
    if proxy_arg:
        print(f"Proxy argument: {proxy_arg}")

    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(file_arg, proxy_arg, user_agent))
