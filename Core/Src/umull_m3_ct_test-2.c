// Timing test of the multiply and divide instructions that handle secret data in the ML-KEM and ML-DSA libraries we
// benchmark, on any Cortex-M with a DWT cycle counter. See the <library>-constant-time.md notes.
// The file name predates the smull, udiv and mul parts.
//
// 1-3. umull, wolfSSL ML-KEM compression: umull lo, hi, v, 0x680bb000 for every v in [0, 3328], controls, size sweeps.
// 4.   smull, PQShield ML-KEM compression: smull lo, hi, 0x004ebedd, (c << 10) + 1665 for every c in [0, 3328].
//      Then controls and size sweeps with negative operands, which also cover the dilithium-lowram NTT
//      (full-range signed operands, no exhaustive domain possible).
// 5.   udiv, STM32PQC poly_tomsg: udiv q, 2t + 1664, 3329 for every t in [0, 3328], controls, size sweeps.
// 6.   mul, mla, mls, the NTT and the Barrett/Montgomery reductions: mul by 20159 (wolfSSL's Barrett constant) and by
//      3329 (q) for every signed 16-bit value, one in each operand order, then controls.
//
// Each exhaustive domain prints its timing classes: CONSTANT when there is only one. The operand order is the one
// found in the libraries' code. The controls show whether the core has data-dependent timing for that instruction
// at all.
//
// Usage: call umull_ct_test() from main() once the clock and UART are initialized.
// It waits for a key press on the UART, runs, prints the results, and loops.
#include <stdint.h>
#include <stdio.h>

#define DEMCR      (*(volatile uint32_t*)0xE000EDFCu)
#define DWT_CTRL   (*(volatile uint32_t*)0xE0001000u)
#define DWT_CYCCNT (*(volatile uint32_t*)0xE0001004u)

#define NREPT 16 // instructions per measurement, must match the .rept count below
#define NRUNS 3  // each measurement is repeated, the minimum is kept, any spread is reported

#define WOLFSSL_UMULL_CONSTANT  0x680bb000u // low word of MLKEM_V54 << 10
#define PQSHIELD_SMULL_CONSTANT 0x004ebeddu // pqs_mlkem_compress_d10
#define MLKEM_Q                 3329u
#define MLKEM_COEF_MAX          3328u
#define BARRETT_V               20159u      // wolfSSL MLKEM_V

int __io_getchar(void);

typedef uint32_t (*insn_timer_fn)(uint32_t rn, uint32_t rm);

// cycles for NREPT back-to-back instructions, plus a fixed overhead (see time_empty)
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
__attribute__((noinline, aligned(32))) static uint32_t time_smull(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, lo, hi;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "smull %[lo], %[hi], %[rn], %[rm]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [lo] "=&r"(lo), [hi] "=&r"(hi)
    : [rn] "r"(rn), [rm] "r"(rm), [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}
__attribute__((noinline, aligned(32))) static uint32_t time_udiv(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, q;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "udiv %[q], %[rn], %[rm]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [q] "=&r"(q)
    : [rn] "r"(rn), [rm] "r"(rm), [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}
__attribute__((noinline, aligned(32))) static uint32_t time_mul(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, d;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "mul %[d], %[rn], %[rm]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [d] "=&r"(d)
    : [rn] "r"(rn), [rm] "r"(rm), [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}
__attribute__((noinline, aligned(32))) static uint32_t time_mla(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, d;
  const uint32_t ra = 0x12345678u;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "mla %[d], %[rn], %[rm], %[ra]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [d] "=&r"(d)
    : [rn] "r"(rn), [rm] "r"(rm), [ra] "r"(ra), [cyc] "r"(&DWT_CYCCNT)
    : "memory");
  return t1 - t0;
}
__attribute__((noinline, aligned(32))) static uint32_t time_mls(uint32_t rn, uint32_t rm){
  uint32_t t0, t1, d;
  const uint32_t ra = 0x12345678u;
  __asm__ volatile(
    "ldr %[t0], [%[cyc]]\n\t"
    ".rept 16\n\t"
    "mls %[d], %[rn], %[rm], %[ra]\n\t"
    ".endr\n\t"
    "ldr %[t1], [%[cyc]]\n\t"
    : [t0] "=&r"(t0), [t1] "=&r"(t1), [d] "=&r"(d)
    : [rn] "r"(rn), [rm] "r"(rm), [ra] "r"(ra), [cyc] "r"(&DWT_CYCCNT)
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
static uint32_t overhead;
static uint32_t measure(insn_timer_fn timer, uint32_t rn, uint32_t rm){
  uint32_t min = UINT32_MAX, max = 0;
  for(unsigned int i = 0; i < NRUNS; i++){
    const uint32_t t = timer(rn, rm);
    if(t < min) min = t;
    if(t > max) max = t;
  }
  if(min != max) spread_count++;
  return min - overhead;
}

static void print_each(uint32_t t){
  printf("%3lu cycles for %d (%lu.%02lu each)", (unsigned long)t, NREPT,
    (unsigned long)(t / NREPT), (unsigned long)((t % NREPT) * 100 / NREPT));
}

// -- exhaustive domains ---------------------------------------------------------------------------------------------
typedef void (*operands_fn)(uint32_t i, uint32_t*rn, uint32_t*rm);

static void check_domain(const char*title, insn_timer_fn timer, operands_fn operands, uint32_t n){
  enum { MAX_CLASSES = 8 };
  uint32_t cycles[MAX_CLASSES], count[MAX_CLASSES], first[MAX_CLASSES], last[MAX_CLASSES];
  unsigned int nclasses = 0, overflow = 0;
  for(uint32_t i = 0; i < n; i++){
    uint32_t rn, rm;
    operands(i, &rn, &rm);
    const uint32_t t = measure(timer, rn, rm);
    unsigned int c = 0;
    while(c < nclasses && cycles[c] != t) c++;
    if(c == nclasses){
      if(nclasses == MAX_CLASSES){ overflow++; continue; }
      cycles[c] = t; count[c] = 0; first[c] = i; nclasses++;
    }
    count[c]++;
    last[c] = i;
  }
  printf("\n%s:\n", title);
  for(unsigned int c = 0; c < nclasses; c++){
    uint32_t rn0, rm0, rn1, rm1;
    operands(first[c], &rn0, &rm0);
    operands(last[c], &rn1, &rm1);
    printf("  ");
    print_each(cycles[c]);
    printf(": %5lu values, first i=%lu (rn=0x%08lx rm=0x%08lx), last i=%lu (rn=0x%08lx rm=0x%08lx)\n",
      (unsigned long)count[c], (unsigned long)first[c], (unsigned long)rn0, (unsigned long)rm0,
      (unsigned long)last[c], (unsigned long)rn1, (unsigned long)rm1);
  }
  if(overflow) printf("  %u values in more than %d timing classes\n", overflow, MAX_CLASSES);
  printf("  => %s\n", (1 == nclasses && 0 == overflow) ? "CONSTANT: one timing for the whole domain" : "NOT CONSTANT");
}

static void umull_wolfssl(uint32_t i, uint32_t*rn, uint32_t*rm){ *rn = i; *rm = WOLFSSL_UMULL_CONSTANT; }
static void smull_pqshield(uint32_t i, uint32_t*rn, uint32_t*rm){ *rn = PQSHIELD_SMULL_CONSTANT; *rm = (i << 10) + 1665u; }
static void udiv_stm32pqc(uint32_t i, uint32_t*rn, uint32_t*rm){ *rn = 2u * i + 1664u; *rm = MLKEM_Q; }
static uint32_t sword16(uint32_t i){ return (uint32_t)(int32_t)(int16_t)(uint16_t)i; }
static void mul_barrett(uint32_t i, uint32_t*rn, uint32_t*rm){ *rn = BARRETT_V; *rm = sword16(i); }
static void mul_q(uint32_t i, uint32_t*rn, uint32_t*rm){ *rn = sword16(i); *rm = MLKEM_Q; }

// -- controls and sweeps --------------------------------------------------------------------------------------------
static void control(const char*label, insn_timer_fn timer, uint32_t rn, uint32_t rm){
  printf("  %-28s rn=0x%08lx rm=0x%08lx: ", label, (unsigned long)rn, (unsigned long)rm);
  print_each(measure(timer, rn, rm));
  printf("\n");
}

static uint32_t pos(unsigned int b){ return (uint32_t)((1ull << b) - 1); }  // 2^b - 1
static uint32_t neg(unsigned int b){ return 0u - (uint32_t)(1ull << b); }   // -2^b, b < 32

// one operand follows pattern(b) for b in [bmin, bmax], the other is fixed; consecutive b with the same timing are
// printed as one range
static void sweep(const char*title, insn_timer_fn timer, uint32_t (*pattern)(unsigned int), unsigned int bmin,
                  unsigned int bmax, int sweep_rn, uint32_t fixed){
  printf("  %s:\n", title);
  unsigned int start = bmin;
  uint32_t t_start = 0;
  for(unsigned int b = bmin; b <= bmax + 1; b++){
    uint32_t t = 0;
    if(b <= bmax){
      const uint32_t v = pattern(b);
      t = sweep_rn ? measure(timer, v, fixed) : measure(timer, fixed, v);
    }
    if(b == bmin){ t_start = t; continue; }
    if(b > bmax || t != t_start){
      printf("    b=%2u..%2u: ", start, b - 1);
      print_each(t_start);
      printf("\n");
      start = b;
      t_start = t;
    }
  }
}

static void run(void){
  spread_count = 0;
  overhead = UINT32_MAX;
  for(unsigned int i = 0; i < NRUNS; i++){
    const uint32_t t = time_empty();
    if(t < overhead) overhead = t;
  }

  // umull: wolfSSL ML-KEM compression
  check_domain("1. umull lo, hi, v, 0x680bb000 for every v in [0, 3328] (wolfSSL ML-KEM)",
    time_umull, umull_wolfssl, MLKEM_COEF_MAX + 1);
  printf("\n2. umull, positive controls:\n");
  control("16 x 16 bits", time_umull, 0xffffu, 0xffffu);
  control("32 x 16 bits", time_umull, 0xffffffffu, 0xffffu);
  control("16 x 32 bits", time_umull, 0xffffu, 0xffffffffu);
  control("32 x 32 bits", time_umull, 0xffffffffu, 0xffffffffu);
  control("v above the domain", time_umull, 0x10000u, WOLFSSL_UMULL_CONSTANT);
  printf("\n3. umull, size sweeps:\n");
  sweep("rn = 2^b - 1, rm = 0x680bb000", time_umull, pos, 1, 32, 1, WOLFSSL_UMULL_CONSTANT);
  sweep("rn = 3328, rm = 2^b - 1", time_umull, pos, 1, 32, 0, MLKEM_COEF_MAX);

  // smull: PQShield ML-KEM compression, signed operands (dilithium-lowram NTT)
  check_domain("4a. smull lo, hi, 0x004ebedd, (c << 10) + 1665 for every c in [0, 3328] (PQShield ML-KEM)",
    time_smull, smull_pqshield, MLKEM_COEF_MAX + 1);
  printf("\n4b. smull, controls:\n");
  control("0 x 0x004ebedd", time_smull, 0u, PQSHIELD_SMULL_CONSTANT);
  control("1 x 0x004ebedd", time_smull, 1u, PQSHIELD_SMULL_CONSTANT);
  control("0x7fff x 0x7fff", time_smull, 0x7fffu, 0x7fffu);
  control("-1 x -1", time_smull, 0xffffffffu, 0xffffffffu);
  control("-0x8000 x 0x7fff", time_smull, 0xffff8000u, 0x7fffu);
  control("-0x10000 x 0x004ebedd", time_smull, 0xffff0000u, PQSHIELD_SMULL_CONSTANT);
  control("0x7fffffff x 0x7fffffff", time_smull, 0x7fffffffu, 0x7fffffffu);
  control("-2^31 x -2^31", time_smull, 0x80000000u, 0x80000000u);
  printf("\n4c. smull, size sweeps:\n");
  sweep("rn = 0x004ebedd, rm = 2^b - 1", time_smull, pos, 1, 31, 0, PQSHIELD_SMULL_CONSTANT);
  sweep("rn = 0x004ebedd, rm = -2^b", time_smull, neg, 0, 31, 0, PQSHIELD_SMULL_CONSTANT);
  sweep("rn = 2^b - 1, rm = 0x004ebedd", time_smull, pos, 1, 31, 1, PQSHIELD_SMULL_CONSTANT);
  sweep("rn = -2^b, rm = 0x004ebedd", time_smull, neg, 0, 31, 1, PQSHIELD_SMULL_CONSTANT);
  sweep("rn = -2^b, rm = -1", time_smull, neg, 0, 31, 1, 0xffffffffu);

  // udiv: STM32PQC poly_tomsg
  check_domain("5a. udiv q, 2t + 1664, 3329 for every t in [0, 3328] (STM32PQC poly_tomsg)",
    time_udiv, udiv_stm32pqc, MLKEM_COEF_MAX + 1);
  printf("\n5b. udiv, controls:\n");
  control("0 / 3329", time_udiv, 0u, MLKEM_Q);
  control("3328 / 3329", time_udiv, 3328u, MLKEM_Q);
  control("3329 / 3329", time_udiv, MLKEM_Q, MLKEM_Q);
  control("0xffffffff / 3329", time_udiv, 0xffffffffu, MLKEM_Q);
  control("0xffffffff / 1", time_udiv, 0xffffffffu, 1u);
  control("1 / 0xffffffff", time_udiv, 1u, 0xffffffffu);
  control("0xffffffff / 0xffffffff", time_udiv, 0xffffffffu, 0xffffffffu);
  printf("\n5c. udiv, size sweeps:\n");
  sweep("rn = 2^b - 1, rm = 3329", time_udiv, pos, 1, 32, 1, MLKEM_Q);
  sweep("rn = 0xffffffff, rm = 2^b - 1", time_udiv, pos, 1, 32, 0, 0xffffffffu);

  // 32-bit multiplies: NTT and reductions
  check_domain("6a. mul d, 20159, v for every signed 16-bit v (wolfSSL Barrett reduction, as compiled)",
    time_mul, mul_barrett, 0x10000u);
  check_domain("6b. mul d, v, 3329 for every signed 16-bit v (the other operand order)",
    time_mul, mul_q, 0x10000u);
  printf("\n6c. mul, mla, mls, controls:\n");
  const insn_timer_fn timers[] = {time_mul, time_mla, time_mls};
  const char*names[] = {"mul", "mla", "mls"};
  for(unsigned int k = 0; k < 3; k++){
    char label[32];
    snprintf(label, sizeof label, "%s 0 x 0xffffffff", names[k]);
    control(label, timers[k], 0u, 0xffffffffu);
    snprintf(label, sizeof label, "%s 0xffff x 0xffff", names[k]);
    control(label, timers[k], 0xffffu, 0xffffu);
    snprintf(label, sizeof label, "%s 0xffffffff x 0xffffffff", names[k]);
    control(label, timers[k], 0xffffffffu, 0xffffffffu);
    snprintf(label, sizeof label, "%s 0x10000 x 0x80000000", names[k]);
    control(label, timers[k], 0x10000u, 0x80000000u);
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
    printf("\npress any key to run the multiply and divide timing test\n");
    __io_getchar();
    __asm__ volatile("cpsid i" ::: "memory");
    run();
    __asm__ volatile("cpsie i" ::: "memory");
  }
}
