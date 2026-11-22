// Exhaustive timing test, on Cortex-M3, of the umull instructions in wolfSSL's ML-KEM ciphertext
// compression (TO_COMP_WORD_10 / TO_COMP_WORD_11 in wolfcrypt/src/wc_mlkem_poly.c).
//
// In every build we benchmark, each of those instructions has the form
//     umull <lo>, <hi>, <coefficient>, <constant>
// with <coefficient> in [0, 3328] (secret dependent during decapsulation) and
// <constant> = 0x680bb000, the low word of MLKEM_V54 << 10 (equal to MLKEM_V53 << 11).
// The coefficient domain has only 3329 values, so timing all of them is a proof, for this silicon,
// that these instructions do not leak the coefficient.
//
// Usage: call umull_ct_test() from main() once the clock and UART are initialized.
// It waits for a key press on the UART, runs, prints the results, and loops.
#include <stdint.h>
#include <stdio.h>

#define DEMCR      (*(volatile uint32_t*)0xE000EDFCu)
#define DWT_CTRL   (*(volatile uint32_t*)0xE0001000u)
#define DWT_CYCCNT (*(volatile uint32_t*)0xE0001004u)

#define MLKEM_UMULL_CONSTANT 0x680bb000u
#define MLKEM_COEF_MAX       3328u
#define NUMULL               16 // must match the .rept count below
#define NRUNS                3  // each measurement is repeated, the minimum is kept, any spread is reported

int __io_getchar(void);

// cycles for NUMULL back-to-back "umull lo, hi, rn, rm", plus a fixed overhead (see time_empty)
// the operand order is the one of the ML-KEM code: rn = coefficient, rm = constant
__attribute__((noinline, aligned(32))) static uint32_t time_umull(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, lo, hi;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "umull %[lo], %[hi], %[rn], %[rm]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [lo] "=&r"(lo), [hi] "=&r"(hi)
    : [rn] "r"(rn), [rm] "r"(rm), [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}
__attribute__((noinline, aligned(32))) static uint32_t time_empty(void){
  uint32_t t0, t1;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1)
    : [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}

static uint32_t spread_count; // measurements whose NRUNS runs did not all agree
static uint32_t measure(uint32_t rn, uint32_t rm){
  uint32_t min = UINT32_MAX, max = 0;
  for(unsigned int i = 0; i < NRUNS; i++){
    const uint32_t t = time_umull(rn, rm);
    if(t < min) min = t;
    if(t > max) max = t;
  }
  if(min != max) spread_count++;
  return min;
}

static uint32_t overhead;
static void print_cycles(const char*label, uint32_t rn, uint32_t rm){
  const uint32_t t = measure(rn, rm) - overhead;
  printf("  %-34s rn=0x%08lx rm=0x%08lx: %3lu cycles for %d umull (%lu.%02lu each)\n", label,
    (unsigned long)rn, (unsigned long)rm, (unsigned long)t, NUMULL,
    (unsigned long)(t / NUMULL), (unsigned long)((t % NUMULL) * 100 / NUMULL));
}

static void run(void){
  spread_count = 0;
  overhead = UINT32_MAX;
  for(unsigned int i = 0; i < NRUNS; i++){
    const uint32_t t = time_empty();
    if(t < overhead) overhead = t;
  }

  // 1. the ML-KEM domain, exhaustively
  enum { MAX_CLASSES = 8 };
  uint32_t class_cycles[MAX_CLASSES], class_count[MAX_CLASSES], class_first[MAX_CLASSES], class_last[MAX_CLASSES];
  unsigned int nclasses = 0, overflow = 0;
  for(uint32_t v = 0; v <= MLKEM_COEF_MAX; v++){
    const uint32_t t = measure(v, MLKEM_UMULL_CONSTANT) - overhead;
    unsigned int c = 0;
    while(c < nclasses && class_cycles[c] != t) c++;
    if(c == nclasses){
      if(nclasses == MAX_CLASSES){ overflow++; continue; }
      class_cycles[c] = t; class_count[c] = 0; class_first[c] = v; nclasses++;
    }
    class_count[c]++;
    class_last[c] = v;
  }
  printf("\n1. umull lo, hi, v, 0x%08lx for every v in [0, %lu]:\n", (unsigned long)MLKEM_UMULL_CONSTANT, (unsigned long)MLKEM_COEF_MAX);
  for(unsigned int c = 0; c < nclasses; c++){
    printf("  %3lu cycles for %d umull: %4lu values, first v=%lu, last v=%lu\n", (unsigned long)class_cycles[c], NUMULL,
      (unsigned long)class_count[c], (unsigned long)class_first[c], (unsigned long)class_last[c]);
  }
  if(overflow) printf("  %u values in more than %d timing classes\n", overflow, MAX_CLASSES);
  printf("  => %s\n", (1 == nclasses && 0 == overflow) ? "CONSTANT: one timing for the whole domain" : "NOT CONSTANT");

  // 2. positive controls: the harness must see the early termination reported by cm-trace
  //    (3 cycles for 0xffff x 0xffff, 4 for 0xffffffff x 0xffff on the STM32F207)
  printf("\n2. positive controls:\n");
  print_cycles("16 x 16 bits", 0xffffu, 0xffffu);
  print_cycles("32 x 16 bits", 0xffffffffu, 0xffffu);
  print_cycles("16 x 32 bits", 0xffffu, 0xffffffffu);
  print_cycles("32 x 32 bits", 0xffffffffu, 0xffffffffu);
  print_cycles("v above the domain", 0x10000u, MLKEM_UMULL_CONSTANT);

  // 3. dependency on the size of each operand, the other one being fixed
  printf("\n3. rn = 2^b - 1, rm = 0x%08lx:\n", (unsigned long)MLKEM_UMULL_CONSTANT);
  for(unsigned int b = 1; b <= 32; b++){
    char label[16];
    snprintf(label, sizeof label, "b=%u", b);
    print_cycles(label, (uint32_t)((1ull << b) - 1), MLKEM_UMULL_CONSTANT);
  }
  printf("\n   rn = %lu, rm = 2^b - 1:\n", (unsigned long)MLKEM_COEF_MAX);
  for(unsigned int b = 1; b <= 32; b++){
    char label[16];
    snprintf(label, sizeof label, "b=%u", b);
    print_cycles(label, MLKEM_COEF_MAX, (uint32_t)((1ull << b) - 1));
  }

  printf("\nmeasurement overhead: %lu cycles, measurements with spread across %d runs: %lu\n",
    (unsigned long)overhead, NRUNS, (unsigned long)spread_count);
}

void umull_ct_test(void){
  setvbuf(stdout, NULL, _IONBF, 0);
  DEMCR |= 1u << 24;  // TRCENA
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1u;     // CYCCNTENA
  while(1){
    printf("\npress any key to run the umull timing test\n");
    __io_getchar();
    __asm__ volatile("cpsid i" ::: "memory");
    run();
    __asm__ volatile("cpsie i" ::: "memory");
  }
}
