#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <string.h>

#include <boost/tokenizer.hpp>

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <map>

#include "mmapped_trie.h"
#include "mmapped_bloom_set.h"

using namespace std;

static const uint64_t BLOOM_REALM_SIZE = 1000000;
static const uint64_t BLOOM_DUPLICATE_SIZE = 100000;
static const uint64_t TRIE_GROUP_DEPTH = 6;
static const uint64_t TRIE_KEYS_DEPTH = 6;
static const uint64_t SHA_LEN = 64;

struct CountHistogram {
  uint16_t counts[21];

  CountHistogram &operator += (const CountHistogram &other) {
    for(int i = 0; i < 21; ++i) {
      counts[i] += other.counts[i];
    }

    return *this;
  }
};

std::string optionError;
std::vector<std::string> messageids;
std::string messageid;
std::string realm;
std::vector<std::string> groups;
std::string key;
std::string rating;

int handle_fail(struct MHD_Connection *connection, const char * /*url*/, const char * /*method*/) {
  std::cerr << "Error: " << optionError << std::endl;
  std::string page = "<html><body>" + optionError + "</body></html>";
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer (page.length(),
      (void *) page.data(), MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
  MHD_destroy_response (response);

  return ret;
}

bool check_sha(const std::string &s) {
  if(s.length() != SHA_LEN) return false;

  for(auto c: s) {
    if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }

  return true;
}

unsigned char base16decode(char c) {
  return (c & 0xF) + (c & 0x40? 9: 0);
}

char base16encode(unsigned char c) {
  static const char *chars = "0123456789abcdef";
  return chars[c];
}

std::string sha_compress(const std::string &s) {
  std::string ret = string(SHA_LEN / 2, ' ');
  for(uint64_t i = 0; i < SHA_LEN / 2; ++i) {
    ret[i] = base16decode(s[i]) << 4 |
             base16decode(s[i + SHA_LEN / 2]);
  }
  return ret;
}

std::string sha_compress_interleaved(const std::string &a, const std::string &b) {
  std::string ret = string(SHA_LEN, ' ');
  for(uint64_t i = 0; i < SHA_LEN; ++i) {
    ret[i] = base16decode(a[i]) << 4 |
             base16decode(b[i]);
  }
  return ret;
}

std::string sha_decompress(const std::string &s) {
  std::string ret = string(SHA_LEN, ' ');
  for(uint64_t i = 0; i < SHA_LEN / 2; ++i) {
    ret[i] = base16encode((static_cast<unsigned char>(s[i]) >> 4) & 0x0F);
    ret[i + SHA_LEN / 2] = base16encode((static_cast<unsigned char>(s[i])) & 0x0F);
  }
  return ret;
}

bool check_duplicate(const std::string &dup) {
  return !MmappedBloomSet(BLOOM_DUPLICATE_SIZE, "duplicates/duplicates").insert(dup);
}

int handle_put(struct MHD_Connection *connection, const char *url, const char *method) {
  if(messageid == "" || rating == "" || key == "") {
    optionError = "messageid, rating and key must be specified (but were not).";
    return handle_fail(connection, url, method);
  }

  for(auto g: groups) {
    if(check_sha(g)) continue;

    optionError = "Invalid group name specified.";
    return handle_fail(connection, url, method);
  }

  if(!check_sha(key)) {
    optionError = "Invalid key specified.";
    return handle_fail(connection, url, method);
  }

  if(!check_sha(messageid)) {
    optionError = "Invalid messageid specified.";
    return handle_fail(connection, url, method);
  }

  int intRating = 0;
  std::istringstream(rating) >> intRating;
  if(intRating < -10) intRating = -10;
  if(intRating > 10) intRating = 10;

  try {
    MmappedTrie<uint64_t, SHA_LEN, TRIE_KEYS_DEPTH> keys("keys/keys");
    const auto &constKeys = keys;

    for(auto g: groups) {
      if(!constKeys[sha_compress_interleaved(key, g)]) {
        optionError = "Insufficient rating allowance on group " + g;
        return handle_fail(connection, url, method);
      }
    }

    if(!check_duplicate(messageid + key)) {
      optionError = "Already rated.";
      return handle_fail(connection, url, method);
    }

    for(auto g: groups) {
      --keys[sha_compress_interleaved(key, g)];
    }

    const std::string compressedMsgId = sha_compress(messageid);

    if(realm != "") {
      if(!check_sha(realm)) {
        optionError = "Invalid realm name";
        return handle_fail(connection, url, method);
      }

      MmappedBloomSet(BLOOM_REALM_SIZE, "realms/" + realm).insert(compressedMsgId);
    }

    for(auto g: groups) {
      ++MmappedTrie<CountHistogram, SHA_LEN / 2, TRIE_GROUP_DEPTH>("groups/" + g)[compressedMsgId].counts[intRating + 11];
    }
  } catch(const std::runtime_error &err) {
    optionError = err.what();
    return handle_fail(connection, url, method);
  }

  const char *page  = "<html><body>Rating counted.</body></html>";
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer (strlen (page),
      (void*) page, MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

int handle_get(struct MHD_Connection *connection, const char *url, const char *method) {
  for(auto g: groups) {
    if(check_sha(g)) continue;

    optionError = "Invalid group name specified.";
    return handle_fail(connection, url, method);
  }

  if(realm != "") {
    if(!check_sha(realm)) {
      optionError = "Invalid realm name";
      return handle_fail(connection, url, method);
    }
  }

  std::map<std::string, CountHistogram> result;

  try {
    if(messageids.size()) {
      for(auto &g: groups) {
        const MmappedTrie<CountHistogram, SHA_LEN / 2, TRIE_GROUP_DEPTH> gr("groups/" + g);

        for(auto &m: messageids) {
          if(!check_sha(m)) {
            optionError = "Invalid messageid specified.";
            return handle_fail(connection, url, method);
          }

          result[m] += gr[sha_compress(m)];
        }
      }
    }

    if(realm != "") {
      MmappedBloomSet r(BLOOM_REALM_SIZE, "realms/" + realm);

      for(auto &g: groups) {
        MmappedTrie<CountHistogram, SHA_LEN / 2, TRIE_GROUP_DEPTH> gr("groups/" + g);

        for(auto m = gr.keys_begin(); m != gr.keys_end(); ++m) {
          if(r.contains(*m)) result[sha_decompress(*m)] += gr[*m];
        }
      }
    }
  } catch(const std::runtime_error &err) {
    optionError = err.what();
    return handle_fail(connection, url, method);
  }

  ostringstream reply;

  reply << "{";
  for(auto &m: result) {
    reply << "\"" << m.first << "\":{\"rating\":[";
    for(int i = 0; i < 21; ++i) {
      reply << m.second.counts[i];

      if(i != 20) reply << ",";
    }
    reply << "],},";
  }
  reply << "}";

  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer (reply.str().length(),
      (void*) reply.str().data(), MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}

int answer_to_connection (void * /*cls*/, struct MHD_Connection *connection,
    const char *url, const char *method, const char * /*version*/, const char * /*upload_data*/,
    size_t * /*upload_data_size*/, void ** /*con_cls*/) {

  if(optionError != "") {
    return handle_fail(connection, url, method);
  } else if(!memcmp(url, "/put/", 5)) {
    return handle_put(connection, url, method);
  } else if(!memcmp(url, "/get/", 5)) {
    return handle_get(connection, url, method);
  } else {
    optionError = "Unknown URI";
    return handle_fail(connection, url, method);
  }
}

void *parse_uri_options(void * /*cls*/, const char *u) {
  std::string url(u);

  optionError = "";
  messageids.clear();
  messageid = "";
  realm = "";
  groups.clear();
  key = "";
  rating = "";

  auto q = url.find('?');
  if(q == string::npos) {
    optionError = "No query string.";
    return 0;
  }

  typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
  const std::string rest = url.substr(q + 1);
  tokenizer params(rest, boost::char_separator<char>("&"));
  for (tokenizer::iterator tok_iter = params.begin(); tok_iter != params.end(); ++tok_iter) {
    tokenizer kv(*tok_iter, boost::char_separator<char>("="));
    const std::string k = *kv.begin();
    const std::string v = *(++kv.begin());

    if(k == "messageids") {
      tokenizer ids(v, boost::char_separator<char>(","));
      std::copy(ids.begin(), ids.end(), back_inserter(messageids));
    } else if(k == "messageid") {
      messageid = v;
    } else if(k == "rating") {
      rating = v;
    } else if(k == "realm") {
      realm = v;
    } else if(k == "groups") {
      tokenizer ids(v, boost::char_separator<char>(","));
      std::copy(ids.begin(), ids.end(), back_inserter(groups));
    } else if(k == "key") {
      key = v;
    } else {
      optionError = "invalid parameter: " + k;
    }
  }

  return 0;
}

int help() {
  std::cerr << "usage ./mailrating server  -- server mode" << std::endl;
  std::cerr << "      ./mailrating auth <key_sha> <group_sha> <count>" << std::endl;
  std::cerr << "                          -- allocate count ratings to key" << std::endl;
  return 1;
}

int main (int argc, const char *argv[]) {
  if(argc < 2) return help();
  if(argv[1] == std::string("server")) {
    struct MHD_Daemon *daemon =
      MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 8080, NULL, NULL, 
          &answer_to_connection, NULL,
          MHD_OPTION_URI_LOG_CALLBACK, &parse_uri_options, NULL,
          MHD_OPTION_END);

    if(!daemon) {
      cerr << "daemon creation failed" << endl;
      return 1;
    }

    char anyKey;
    cin.get(anyKey);

    MHD_stop_daemon(daemon);

    return 0;
  } else if(argv[1] == std::string("auth")) {
    if(argc != 5) return help();

    const std::string key = argv[2];
    const std::string group = argv[3];
    int count = 0;
    istringstream(argv[4]) >> count;

    if(!count) throw std::runtime_error("Invalid count");
    if(!check_sha(key)) throw std::runtime_error("Invalid key");
    if(!check_sha(group)) throw std::runtime_error("Invalid group");

    MmappedTrie<uint64_t, SHA_LEN, TRIE_KEYS_DEPTH> keys("keys/keys");
    keys[sha_compress_interleaved(key, group)] = count;
  }
}
