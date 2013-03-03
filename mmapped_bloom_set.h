#ifndef MMAPPED_BLOOMSET_H
#define MMAPPED_BLOOMSET_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <strings.h>

#include <iostream>
#include <string>
#include <stdexcept>

/* A file-backed bloom set implementation (see https://en.wikipedia.org/wiki/Bloom_filter for the idea)
 *
 * The implementation is fixed-size, i.e. the bloom filter cannot be resized during operations.
 * It works by mmap(2)ing the whole bit array as a file, thereby providing cheap persistence.
 *
 * Usage example:
 *   MmappedBloomSet b(1000, "foo");       // create new bloom set, expecting max. 1000 elements, store in file called "foo"
 *   b.insert("Ohai");                     // insert "Ohai" into set
 *   if(!b.contains("Ohai")) { // never }  // test for set membership
 *   if(b.insert("Ohai"))    { // always } // insert "Ohai" again, find out it was already there
 */
class MmappedBloomSet {
  private:
    static const uint64_t INITIAL_ALLOC = 65536;

  public:
    // Create a new bloom set.
    //   expectedElements: number of elements we expect this bloom set to hold maximally
    //   file: what file to use for storage (created if non-existent)
    MmappedBloomSet(uint64_t expectedElements, const std::string &file) {
      if(expectedElements == 0) expectedElements = 2;

      // let's aim for ~0.0001 probability
      bits = expectedElements * 20;
      keybits = 7 * bits / expectedElements / 10;
      uint64_t shouldAlloc = (((bits / 8 + 1) - 1) / INITIAL_ALLOC + 1) * INITIAL_ALLOC;

      fd = open(file.c_str(), O_RDWR | O_CREAT, 0666);
      if(fd < 0) throw std::runtime_error("Could not open " + file + ": " + strerror(errno));

      struct stat stats;
      int s = fstat(fd, &stats);
      if(s < 0) throw std::runtime_error("Could not stat " + file + ": " + strerror(errno));

      alloc = stats.st_size;
      if(alloc < shouldAlloc) {
        char zero[INITIAL_ALLOC] = { 0 };
        int ret;

        lseek(fd, alloc, SEEK_SET);
        for(uint64_t todo = shouldAlloc - alloc; todo; todo -= ret) {
          std::cout << todo << std::endl;
          ret = write(fd, zero, INITIAL_ALLOC);
          if(ret < 0) throw std::runtime_error("Write failed while extending bloom set: " + std::string(strerror(errno)));
        }
      }

      alloc = shouldAlloc;

      data = static_cast<unsigned char *>(mmap(0, alloc, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
      if(data == MAP_FAILED) throw std::runtime_error("Could not mmap " + file + ": " + strerror(errno));
    }

    ~MmappedBloomSet() {
      int ret = munmap(data, alloc);
      if(ret < 0) throw std::runtime_error("Should never happen, munmap failed: " + std::string(strerror(errno)));

      ret = close(fd);
      if(ret < 0) throw std::runtime_error("Should never happen, close failed: " + std::string(strerror(errno)));
    }

    bool contains(const char *str, const size_t n) { return countBits(str, n) >= keybits; }
    bool contains(const std::string &s) { return contains(s.c_str(), s.length()); }

    // return true if the element already existed
    bool insert(const char *str, const size_t n) { return setBits(str, n) >= keybits; }
    bool insert(const std::string &s) { return insert(s.c_str(), s.length()); }

    // return estimated raw fill state in promille
    // an optimally used bloom filter should return 500
    int estimateFill() {
      int fill = 0;
      unsigned int max = 256;
      if(bits / 8 < max) max = bits / 8;

      for(unsigned int i = 0; i < max; ++i) fill += data[i] & 1;
      return (fill * 1000) / max;
    }

  private:
    int fd;
    uint64_t alloc;

    uint64_t bits;
    uint64_t keybits;
    unsigned char *data;

    unsigned int setBits(const char *str, const size_t n) {
      unsigned int count = 0;
      uint64_t index = 0;

      for(unsigned int i = 0; i < keybits; ++i) {
        index = nextBit(index, str, n, i);
        count +=!! (data[(index % bits) / 8] & (1 << ((index % bits) % 8)));
        data[(index % bits) / 8] |= 1 << ((index % bits) % 8);
      }

      return count;
    }

    unsigned int countBits(const char *str, const size_t n) {
      unsigned int count = 0;
      uint64_t index = 0;

      for(unsigned int i = 0; i < keybits; ++i) {
        index = nextBit(index, str, n, i);
        count +=!! (data[(index % bits) / 8] & (1 << ((index % bits) % 8)));
      }

      return count;
    }

    uint64_t nextBit(uint64_t lastBit, const char *str, const size_t n, char bitNo) {
      uint64_t magic[] = {
        0xF567789806898063ull,
        0x4567779816798165ull,
        0xC567769826698267ull,
        0x4567759836598369ull,
        0xD567749846498461ull,
        0x4567739856398563ull,
        0xE567729866298667ull,
        0x4567719876198765ull,
      };
      const char *e = str + n;

      while(str < e - 7) {
        lastBit = (lastBit ^ 17) + *reinterpret_cast<const uint64_t *>(str) * magic[bitNo % 8] + (lastBit >> 8);
        str += 8;
      }
      if(str < e - 3) {
        lastBit = (lastBit ^ 17) + *reinterpret_cast<const uint32_t *>(str) * magic[bitNo % 8] + (lastBit >> 8);
        str += 4;
      }
      if(str < e - 1) {
        lastBit = (lastBit ^ 17) + *reinterpret_cast<const uint16_t *>(str) * magic[bitNo % 8] + (lastBit >> 8);
        str += 2;
      }
      if(str < e) {
        lastBit = (lastBit ^ 17) + *reinterpret_cast<const uint8_t *>(str) * magic[bitNo % 8] + (lastBit >> 8);
      }

      return lastBit;
    }
};

#endif
