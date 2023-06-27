import string
import urllib.parse
from multiprocessing.dummy import Pool
from os.path import exists
from random import choice, randint
from time import sleep

import requests
import tls_client
import tls_client.sessions
from pyuseragents import random as random_useragent

from utils import logger, solve_captcha

headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'ru,en;q=0.9',
    'content-type': 'application/json',
    'origin': 'https://www.playbux.co',
    'referer': 'https://www.playbux.co/'
}

email_headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'ru,en;q=0.9',
    'content-type': 'application/json',
    'origin': 'https://www.emailnator.com',
    'referer': 'https://www.emailnator.com/',
    'x-requested-with': 'XMLHttpRequest'
}


def generate_password() -> str:
    length = randint(10, 20)
    characters = string.ascii_letters + string.digits + '#_?&.,!'
    random_string = choice(string.ascii_lowercase) + choice(string.ascii_uppercase)
    random_string += choice(string.digits)
    random_string += choice('#_?&.,!')

    for _ in range(length - 4):
        random_string += choice(characters)

    return random_string


def bypass_email_errors(current_function,
                        **kwargs):
    try:
        return current_function(**kwargs)

    except Exception as error:
        logger.error(f'Неизвестная ошибка: {error}')

        return bypass_email_errors(current_function=current_function,
                                   **kwargs)


class EmailNator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            **email_headers,
            'user-agent': random_useragent()
        })

    def get_email_csrf_token(self,
                             url: str):
        r = self.session.get(url=url,
                             headers={
                                 **self.session.headers,
                                 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,'
                                           'image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                 'accept-language': 'ru,en;q=0.9'
                             })

        return r.cookies['XSRF-TOKEN']

    def get_email(self) -> str:
        xsrf_token: str = self.get_email_csrf_token(url='https://www.emailnator.com/')

        r = self.session.post('https://www.emailnator.com/generate-email',
                              json={
                                  'email': ['dotGmail']
                              },
                              headers={
                                  **self.session.headers,
                                  'x-xsrf-token': urllib.parse.unquote(string=xsrf_token)
                              })
        return r.json()['email'][0]

    def get_messages(self,
                     target_email: str) -> list:
        xsrf_token: str = self.get_email_csrf_token(url=f'https://www.emailnator.com/inbox#{target_email}#')

        r = self.session.post(url='https://www.emailnator.com/message-list',
                              json={
                                  'email': target_email
                              },
                              headers={
                                  **self.session.headers,
                                  'x-xsrf-token': urllib.parse.unquote(string=xsrf_token)
                              })

        return r.json()['messageData']

    def get_message(self,
                    target_email: str,
                    message_id: str) -> str:
        xsrf_token: str = self.get_email_csrf_token(url=f'https://www.emailnator.com/inbox/{target_email}/{message_id}')

        r = self.session.post(url='https://www.emailnator.com/message-list',
                              json={
                                  'email': target_email,
                                  'messageID': message_id
                              },
                              headers={
                                  **self.session.headers,
                                  'x-xsrf-token': urllib.parse.unquote(string=xsrf_token)
                              })

        return r.text


class AutoReger:
    def __init__(self,
                 account_proxy: str | None) -> None:
        self.account_proxy: str | None = account_proxy

        self.account_email: str = ''
        self.account_password: str = ''

        self.session = tls_client.Session(client_identifier=choice(['chrome_103',
                                                                    'chrome_104',
                                                                    'chrome_105',
                                                                    'chrome_106',
                                                                    'chrome_107',
                                                                    'chrome_108',
                                                                    'chrome109',
                                                                    'Chrome110',
                                                                    'chrome111',
                                                                    'chrome112',
                                                                    'firefox_102',
                                                                    'firefox_104',
                                                                    'firefox108',
                                                                    'Firefox110',
                                                                    'opera_89',
                                                                    'opera_90']),
                                          random_tls_extension_order=True)
        self.session.headers.update({
            **headers,
            'user-agent': random_useragent()
        })

        if self.account_proxy: self.session.proxies.update({
            'http': self.account_proxy,
            'https': self.account_proxy
        })

    def send_register_request(self,
                              captcha_response: str) -> bool:
        try:
            r = self.session.post(url='https://www.playbux.co/api/v2/auth/register',
                                  json={
                                      'agree': True,
                                      'confirmPassword': self.account_password,
                                      'email': self.account_email,
                                      'password': self.account_password,
                                      'recaptchaToken': captcha_response,
                                      'token': ''
                                  })

            if r.status_code == 201:
                return True

            logger.error(f'{self.account_email} | Неверный ответ при отправке запроса на '
                         f'регистрацию, статус ответа: {r.status_code}')

            return False

        except Exception as error:
            logger.error(f'Ошибка при отправке запроса на регистрацию: {error}')

            return self.send_register_request(captcha_response=captcha_response)

    def verify_account(self,
                       verify_url: str) -> bool:
        try:
            r = self.session.get(url=verify_url,
                                 allow_redirects=True)

            return True if r.status_code == 200 else False

        except Exception as error:
            logger.error(f'{self.account_email} | Ошибка при подтверждении аккаунта: {error}')

            return self.verify_account(verify_url=verify_url)

    def main(self):
        self.account_password: str = generate_password()
        self.account_email: str = email_nator.get_email()
        captcha_response: str = solve_captcha(proxy=self.account_proxy,
                                              account_email=self.account_email)

        logger.info(f'{self.account_email} | Капча успешно решена')

        send_register_request_result: bool = self.send_register_request(captcha_response=captcha_response)

        if not send_register_request_result:
            return

        logger.success(f'{self.account_email} | Запрос на регистрацию успешно отправлен, ожидаю письмо')

        for _ in range(10):
            sleep(6)
            received_messages: list = email_nator.get_messages(target_email=self.account_email)

            for current_message in received_messages:
                if current_message['from'] == 'noreply@playbux.co':
                    message_id: str = current_message['messageID']

                    logger.success(f'{self.account_email} | Письмо получено')

                    break

            else:
                continue

            break

        else:
            logger.error(f'{self.account_email} | Не удалось дождаться письма')
            return

        message_text: str = email_nator.get_message(target_email=self.account_email,
                                                    message_id=message_id)
        verify_url: str = 'https://u31612980.ct.sendgrid.net/ls/click?' + \
                          message_text.split('href="https://u31612980.ct.sendgrid.net/ls/click?')[-1].split('"')[0]
        verify_account_result: bool = self.verify_account(verify_url=verify_url)

        if verify_account_result:
            with open(file='registered_accounts.txt', mode='a', encoding='utf-8-sig') as f:
                f.write(f'{self.account_email}:{self.account_password}\n')

            logger.success(f'{self.account_email}:{self.account_password}')

        else:
            logger.error(f'{self.account_email}:{self.account_password}')


def wrapper(_) -> None:
    while True:
        try:
            if proxy_list:
                random_proxy_str: str = choice(proxy_list)

                if change_proxy_url:
                    r = requests.get(url=change_proxy_url)

                    logger.info(f'Статус ответа на запрос для смены Proxy: {r.status_code}')

            else:
                random_proxy_str: None = None

            AutoReger(account_proxy=random_proxy_str).main()

        except Exception as error:
            logger.error(f'Неизвестная ошибка: {error}')


if __name__ == '__main__':
    email_nator = EmailNator()

    proxy_folder: str | None = None
    change_proxy_url: str | None = None
    proxy_list: list = None

    threads: int = int(input('Threads: '))
    use_proxies: str = input('Использовать Proxy? (y/N): ').lower()

    if use_proxies == 'y':
        proxy_folder: str = input('Перетяните .txt, в котором каждый Proxy указан с новой строки '
                                  '(type://user:pass@ip:port or type://ip:port), либо введите прокси строкой: ')

        if not exists(path=proxy_folder):
            change_proxy_url: str = input('Если вы используете мобильные Proxy со сменой по ссылке, '
                                          'то введите ссылку для смены IP (В протвином случае нажмите Enter): ')

            if not change_proxy_url:
                change_proxy_url: None = None

            proxy_list: list = [proxy_folder]

        else:
            with open(proxy_folder, 'r', encoding='utf-8-sig') as file:
                proxy_list: list = [row.strip() for row in file]

    print('')

    with Pool(processes=threads) as executor:
        executor.map(wrapper, [None for _ in range(threads)])
