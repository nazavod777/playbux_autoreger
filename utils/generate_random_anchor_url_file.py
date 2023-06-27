import random
import string
import urllib.parse


def generate_random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))


url = "https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LfBM9AgAAAAAMjPaQDEfiGRhGnFIkBd8BwWsJ6c&co=aHR0cHM6Ly93d3cucGxheWJ1eC5jbzo0NDM.&hl=en&v=IqA9DpBOUJevxkykws9RiIBs&size=invisible&cb=e5ypc8xmx1k6"

parsed_url = urllib.parse.urlparse(url)
query_params = urllib.parse.parse_qs(parsed_url.query)


def generate_random_anchor_url() -> str:
    if "v" in query_params:
        query_params["v"][0] = generate_random_string(10)

    if "cb" in query_params:
        query_params["cb"][0] = generate_random_string(10)

    new_query_string = urllib.parse.urlencode(query_params, doseq=True)
    new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query_string))

    return new_url
