==== Problem ====

* Your users want to like or dislike items. There are many items and many users.
* You have a tiny vServer. Some of your users are evil (but you don't know which ones).
* Some users would like to only see ratings of a certain subset of other users.
* Items are grouped by realms, it would be nice if users could get ratings of a single realm combined.

One example: http://padtest.piraten-nds.de/p/dezentrale-mailbewertung

==== Solution ====

SHA256 everything: Users, items (identified by something), user groups, realms.

Data structures:

realm: Bloom<Message-ID> (per week or month)

group: Trie<Message-ID -> Histogram> (per month or year)

duplicate-filter: Bloom<User:Message-ID> (per day or hour)
cleared after a while, rating not possible for expired duplicate zones (must be done by client)
