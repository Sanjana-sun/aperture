#!/usr/bin/env python3
"""Regenerate Aperture's test fixtures.

The synthetic export is checked in as a binary, which means nothing in the repo
explains where its numbers come from. This script is that explanation, and it is
deterministic, so regenerating it produces a byte-identical archive.

Nothing here is real data. The location trace is a plausible shape (a home
cluster, a weekday commute to a work cluster, a gym, and three days away) because
a straight line or a uniform scatter does not show what a real trace gives away.
"""
import json, os, random, zipfile

SEED = 7
HOME, WORK = (42.3601, -71.0589), (42.3398, -71.0892)
GYM, TRIP = (42.3467, -71.0972), (42.4430, -71.2290)
DAY = 86400

BRANDS = ["Northline Outfitters", "Cedar & Co", "Harborview Dental", "Kestrel Fitness",
          "BlueRoute Insurance", "PaperLane Books", "Grove Market", "Tidewater Realty",
          "Nimbus Telecom", "Fernwood Clinic", "Aster Cosmetics", "Redbrick Motors",
          "Lantern Travel", "Copperfield Bank", "Vale Pharmacy", "Selkie Apparel",
          "Ironwood Gym", "Cloudberry Foods", "Marlowe Legal", "Pinecrest Vet"]
PLACES = ["Allston", "Brookline", "Cambridge", "Davis Sq", "Fenway", "Quincy", "Revere",
          "Somerville", "Southie", "Waltham", "Watertown", "Medford", "Malden", "Newton",
          "Arlington", "Belmont", "Chelsea"]
INTERESTS = ["Running", "Photography", "Home improvement", "Travel", "Personal finance",
             "Cooking", "Yoga", "Cycling", "Parenting", "Real estate", "Job seeking",
             "Weight loss", "Dating", "Gaming", "Luxury goods", "Cryptocurrency",
             "Pet owners", "New movers", "Political news", "Fertility", "Mental health",
             "Debt consolidation", "Vegetarian", "Recently engaged", "Small business owner"]


def location_history(rng, days=50, start=1700000000):
    pts = []
    for day in range(days):
        t = start + day * DAY + 6 * 3600          # each loop is one real calendar day
        for _ in range(rng.randint(6, 10)):       # overnight and morning at home
            pts.append(point(rng, HOME, t)); t += 1800
        if day % 7 not in (5, 6):                 # weekdays only
            for k in range(6):                    # the commute, interpolated
                f = k / 5
                pts.append({"lat": round(HOME[0] + (WORK[0] - HOME[0]) * f + rng.gauss(0, 7e-4), 6),
                            "lon": round(HOME[1] + (WORK[1] - HOME[1]) * f + rng.gauss(0, 7e-4), 6),
                            "ts": t}); t += 600
            for _ in range(rng.randint(8, 14)):
                pts.append(point(rng, WORK, t)); t += 1800
        if day % 3 == 0:
            for _ in range(3):
                pts.append(point(rng, GYM, t, 8e-4)); t += 1200
        if day in (12, 13, 31):                   # three days out of town
            for _ in range(20):
                pts.append(point(rng, TRIP, t, 6e-3)); t += 2400
    return pts


def point(rng, centre, t, spread=1.6e-3):
    return {"lat": round(centre[0] + rng.gauss(0, spread), 6),
            "lon": round(centre[1] + rng.gauss(0, spread), 6), "ts": t}


def build(path):
    rng = random.Random(SEED)
    pts = location_history(rng)
    # Distinct businesses, shuffled: a real advertiser list is not grouped by brand.
    advertisers = [f"{b} {p}" for b in BRANDS for p in PLACES][:340]
    rng.shuffle(advertisers)
    assert len(set(advertisers)) == 340
    logins = [{"ip": rng.choice(["73.114.28.9"] * 3 + ["10.0.4.77", "98.207.11.3"]),
               "ua": "Mozilla/5.0", "ts": 1700000000 + i * 7200} for i in range(200)]

    files = {
        'personal_information/profile.json': {
            "name": "Sanjana Injamuri", "email": "sanjana.test@example.com",
            "phone": "+1 774 465 9562", "birthday": "1999-04-12",
            "registration_ip": "73.114.28.9"},
        'ads_information/advertisers_using_your_activity.json': {
            "advertisers": [{"name": n, "has_data_file_custom_audience": True} for n in advertisers]},
        'ads_information/ad_preferences.json': {"interests": INTERESTS},
        'ads_information/inferred_topics.json': {"inferred_topic": INTERESTS[:14]},
        'location/primary_location.json': {"city": "Boston, MA", "inferred": True},
        'location/location_history.json': {"points": pts},
        'messages/inbox/thread_1/message_1.json': {
            "messages": [{"sender": "A", "content": "see you at 7"}] * 80},
        'connections/followers.json': {"followers": [f"user{i}" for i in range(900)]},
        'security_and_login/login_activity.json': {"logins": logins},
        'device_information/devices.json': {"devices": [{"model": "iPhone 14", "id": "ABC-123"}]},
        'posts/your_posts.json': {"posts": [{"text": "hello world"}] * 50},
    }
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, obj in files.items():
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, json.dumps(obj))
        z.writestr(zipfile.ZipInfo('README.txt', date_time=(2026, 1, 1, 0, 0, 0)),
                   'Synthetic export for demonstrating Aperture. No real data.')
    print(f"{path}: {len(pts)} location points, {len(advertisers)} advertisers, "
          f"{os.path.getsize(path)} bytes")


if __name__ == '__main__':
    here = os.path.dirname(os.path.abspath(__file__))
    build(os.path.join(here, 'export.zip'))
