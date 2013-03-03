#ifndef MMAPED_TRIE_H
#define MMAPED_TRIE_H

#include <cstdint>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdexcept>

/* A file-backed trie implementation (see https://en.wikipedia.org/wiki/Trie for the idea)
 *
 * The implementation grows the underlying file as the trie grows.
 * It works by mmap(2)ing the whole memory, thereby providing cheap persistence.
 *
 * Usage example:
 *   MmappedTrie<int, 8, 2> t("foo");                     // create a new trie, backed by file "foo", mapping strings
 *                                                        // of length 8 to ints, but only using the first 2 characters
 *                                                        // to bulid tree paths
 *   t["01234567"] = 4;                                   // store a 4 at "01234567"
 *   for(auto i = t.keys_begin(); i != keys_end(); ++i) { // iterate all keys in alphabetical order
 *     std::cout << *i << ": " << t[*i] << std::endl;
 *   }
 */
template<class V, int keylen, int triedepth> class MmappedTrie {
  private:
    struct InnerNode {
      uint64_t next[16];
    };

    struct LeafNode {
      char postfix[keylen - triedepth];
      V v;
      uint64_t next;
    };

    static const uint64_t INITIAL_ALLOC = 65536;
    static const uint64_t FIRST_NODE_OFFSET = sizeof(uint64_t);
    static const uint64_t MAX_LEAF_WALK = 32;

    int fd;
    void *memory;
    uint64_t alloc;

    template<class T> T *at(uint64_t off) {
      if(alloc < off + sizeof(T)) {
        munmap(memory, alloc);

        lseek(fd, alloc, SEEK_SET);

        char zero[INITIAL_ALLOC] = { 0 };
        int ret;

        for(uint64_t todo = alloc; todo; todo -= ret) {
          ret = write(fd, zero, INITIAL_ALLOC);
          if(ret < 0) throw std::runtime_error("Write failed while extending trie: " + std::string(strerror(errno)));
        }

        alloc *= 2;

        memory = mmap(0, alloc, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if(memory == MAP_FAILED) throw std::runtime_error("Could not mmap while extending trie: " + std::string(strerror(errno)));
      }
      
      return reinterpret_cast<T *>(static_cast<char *>(memory) + off);
    }

    template<class T> T *at(uint64_t off) const {
      if(alloc < off + sizeof(T)) throw std::logic_error("Invalid trie extension attempted while being const");
      return reinterpret_cast<T *>(static_cast<char *>(memory) + off);
    }

    uint64_t &fill() {
      return *at<uint64_t>(0);
    }

    template<class T> uint64_t create() {
      const uint64_t ret = fill();
      fill() += sizeof(T);
      return ret;
    }

  public:
    MmappedTrie(const std::string &file): def() {
      fd = open(file.c_str(), O_RDWR | O_CREAT, 0666);
      if(fd < 0) throw std::runtime_error("Could not open " + file + ": " + strerror(errno));

      struct stat stats;
      int s = fstat(fd, &stats);
      if(s < 0) throw std::runtime_error("Could not stat " + file + ": " + strerror(errno));

      alloc = stats.st_size;
      if(alloc < INITIAL_ALLOC) {
        char zero[INITIAL_ALLOC] = { 0 };
        write(fd, zero, INITIAL_ALLOC);
        alloc = INITIAL_ALLOC;
      }

      memory = mmap(0, alloc, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if(memory == MAP_FAILED) throw std::runtime_error("Could not mmap " + file + ": " + strerror(errno));

      if(!fill()) {
        fill() = FIRST_NODE_OFFSET + sizeof(InnerNode);
      }
    }

    ~MmappedTrie() {
      int ret = munmap(memory, alloc);
      if(ret < 0) throw std::runtime_error("Should never happen, munmap failed: " + std::string(strerror(errno)));

      ret = close(fd);
      if(ret < 0) throw std::runtime_error("Should never happen, close failed: " + std::string(strerror(errno)));
    }
    
    V &operator [] (const std::string &key) {
      if(key.length() != keylen) throw std::runtime_error("Invalid key length in key: " + key);

      uint64_t node = FIRST_NODE_OFFSET;

      for(int i = 0; i < triedepth - 1; ++i) {
        {
          uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[i]) & 0xF0) >> 4];
          if(!next) next = create<InnerNode>();
          node = next;
        } {
          uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[i]) & 0x0F)];
          if(!next) next = create<InnerNode>();
          node = next;
        }
      }

      {
        uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[triedepth - 1]) & 0xF0) >> 4];
        if(!next) next = create<InnerNode>();
        node = next;
      } {
        uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[triedepth - 1]) & 0x0F)];
        if(!next) {
          next = create<LeafNode>();
          LeafNode &newLeaf = *at<LeafNode>(next);
          memcpy(newLeaf.postfix, key.data() + triedepth, keylen - triedepth);
          return newLeaf.v;
        }
        node = next;
      }

      for(uint64_t i = 0; i < MAX_LEAF_WALK; ++i) {
        LeafNode &leaf = *at<LeafNode>(node);

        if(!memcmp(leaf.postfix, key.data() + triedepth, keylen - triedepth)) return leaf.v;
        if(!leaf.next) {
          leaf.next = create<LeafNode>();
          LeafNode &newLeaf = *at<LeafNode>(leaf.next);
          memcpy(newLeaf.postfix, key.data() + triedepth, keylen - triedepth);
          return newLeaf.v;
        }

        node = leaf.next;
      }

      throw std::runtime_error("leaf walk too lengthy, aborting");
    }

    const V def;

    const V &operator [] (const std::string &key) const {
      if(key.length() != keylen) throw std::runtime_error("Invalid key length in key: " + key);

      uint64_t node = FIRST_NODE_OFFSET;

      for(int i = 0; i < triedepth - 1; ++i) {
        {
          uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[i]) & 0xF0) >> 4];
          if(!next) return def;
          node = next;
        } {
          uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[i]) & 0x0F)];
          if(!next) return def;
          node = next;
        }
      }

      {
        uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[triedepth - 1]) & 0xF0) >> 4];
        if(!next) return def;
        node = next;
      } {
        uint64_t &next = at<InnerNode>(node)->next[(static_cast<unsigned char>(key[triedepth - 1]) & 0x0F)];
        if(!next) return def;
        node = next;
      }

      for(uint64_t i = 0; i < MAX_LEAF_WALK; ++i) {
        LeafNode &leaf = *at<LeafNode>(node);

        if(!memcmp(leaf.postfix, key.data() + triedepth, keylen - triedepth)) return leaf.v;
        if(!leaf.next) return def;

        node = leaf.next;
      }

      throw std::runtime_error("leaf walk too lengthy, aborting");
    }

    class keys_iterator {
      private:
        uint64_t offsets[triedepth * 2 + 1];
        std::string key;
        MmappedTrie &trie;

      public:
        keys_iterator(MmappedTrie &trie): trie(trie) {
          offsets[0] = FIRST_NODE_OFFSET;
          for(int i = 1; i < triedepth * 2 + 1; ++i) {
            offsets[i] = 0;
          }
          key = "";
        }

        friend class MmappedTrie;

        bool operator == (const keys_iterator &o) const {
          return key == o.key;
        }
        bool operator != (const keys_iterator &o) const { return !(*this == o); }

        const std::string &operator * () const { return key; }

        keys_iterator &operator ++ () {
          if(offsets[triedepth * 2]) {
            if(trie.at<LeafNode>(offsets[triedepth * 2])->next) {
              offsets[triedepth * 2] = trie.at<LeafNode>(offsets[triedepth * 2])->next;

              for(int j = 0; j < keylen - triedepth; ++j) {
                key[triedepth + j] = trie.at<LeafNode>(offsets[triedepth * 2])->postfix[j];
              }

              return *this;
            }
          }

          offsets[triedepth * 2] = 0;

          int i;
          for(i = triedepth * 2 - 1; i >= 0; --i) {
            if(offsets[i]) {
              bool walkhere = false;

              for(int j = ((static_cast<unsigned char>(key[i / 2]) >> (i % 2? 0: 4)) & 0x0F) + 1; j < 16; ++j) {
                if(trie.at<InnerNode>(offsets[i])->next[j]) {
                  offsets[i + 1] = trie.at<InnerNode>(offsets[i])->next[j];
                  key[i / 2] = (static_cast<unsigned char>(key[i / 2]) & (0x0F << (i % 2? 4: 0)))
                                                                       | (j    << (i % 2? 0: 4));
                  walkhere = true;
                  break;
                }
              }

              if(walkhere) {
                ++i;
                break;
              }
              offsets[i] = 0;
            }
          }

          if(!offsets[0]) {
            key = "";
            return *this;
          }

          for(; i < triedepth * 2; ++i) {
            bool any = false;
            for(int j = 0; j < 16; ++j) {
              if(trie.at<InnerNode>(offsets[i])->next[j]) {
                offsets[i + 1] = trie.at<InnerNode>(offsets[i])->next[j];
                key[i / 2] = (static_cast<unsigned char>(key[i / 2]) & (0x0F << (i % 2? 4: 0)))
                                                                     | (j    << (i % 2? 0: 4));
                any = true;
                break;
              }
            }

            if(!any) throw std::logic_error("trie inconsistency, did not reach leaf while iterating");
          }

          for(int j = 0; j < keylen - triedepth; ++j) {
            key[triedepth + j] = trie.at<LeafNode>(offsets[triedepth * 2])->postfix[j];
          }

          return *this;
        }
    };

    keys_iterator keys_begin() {
      keys_iterator ret(*this);
      for(int i = 0; i < keylen; ++i) {
        ret.key += '\0';
      }
      return ++ret;
    }

    keys_iterator keys_end() {
      return keys_iterator(*this);
    }
};

#endif
