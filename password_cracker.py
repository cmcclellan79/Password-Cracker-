import time
import itertools
import string
import json
from collections import Counter
from datetime import datetime

class PasswordCracker:
    """
    Educational brute-force password cracker with data analysis capabilities.
    For authorized security testing, CTF challenges, and educational purposes only.
    """

    def __init__(self, password, max_length=6, charset=None, verbose=True):
        self.password = password
        self.max_length = max_length
        self.charset = charset or (string.ascii_letters + string.digits + string.punctuation)
        self.verbose = verbose

        # Analytics data
        self.attempts = 0
        self.start_time = None
        self.end_time = None
        self.found = False
        self.cracked_password = None
        self.length_attempts = {}
        self.charset_hits = Counter()
        self.time_checkpoints = []

    def analyze_password_complexity(self):
        """Analyze the target password's complexity metrics"""
        analysis = {
            'length': len(self.password),
            'has_lowercase': any(c in string.ascii_lowercase for c in self.password),
            'has_uppercase': any(c in string.ascii_uppercase for c in self.password),
            'has_digits': any(c in string.digits for c in self.password),
            'has_special': any(c in string.punctuation for c in self.password),
            'unique_chars': len(set(self.password)),
            'character_types': 0
        }

        # Calculate character type diversity
        if analysis['has_lowercase']:
            analysis['character_types'] += 1
        if analysis['has_uppercase']:
            analysis['character_types'] += 1
        if analysis['has_digits']:
            analysis['character_types'] += 1
        if analysis['has_special']:
            analysis['character_types'] += 1

        # Calculate theoretical search space
        charset_size = len(self.charset)
        analysis['search_space'] = sum(charset_size ** i for i in range(1, self.max_length + 1))
        analysis['exact_length_space'] = charset_size ** len(self.password)

        return analysis

    def estimate_theoretical_time(self):
        """Estimate theoretical crack time based on charset and password length"""
        charset_size = len(self.charset)
        password_length = len(self.password)

        # Worst case: need to try all combinations up to password length
        total_combinations = sum(charset_size ** i for i in range(1, password_length + 1))

        return {
            'total_combinations': total_combinations,
            'charset_size': charset_size,
            'password_length': password_length
        }

    def crack(self):
        """Execute brute-force attack with detailed tracking"""
        self.start_time = time.time()

        if self.verbose:
            print(f"{'='*70}")
            print(f"[INIT] Starting Brute-Force Password Cracker")
            print(f"{'='*70}")
            print(f"[CONFIG] Max Length: {self.max_length}")
            print(f"[CONFIG] Charset Size: {len(self.charset)}")
            print(f"[CONFIG] Charset: {self.charset[:50]}..." if len(self.charset) > 50 else f"[CONFIG] Charset: {self.charset}")

            theoretical = self.estimate_theoretical_time()
            print(f"[ESTIMATE] Search Space: {theoretical['total_combinations']:,} combinations")
            print(f"{'='*70}\n")

        for length in range(1, self.max_length + 1):
            if self.verbose:
                print(f"[PHASE] Testing passwords of length {length}...")

            length_start = self.attempts

            for guess_tuple in itertools.product(self.charset, repeat=length):
                guess = ''.join(guess_tuple)
                self.attempts += 1

                # Track character usage in attempts
                for char in guess:
                    self.charset_hits[char] += 1

                # Periodic progress updates
                if self.verbose and self.attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    self.time_checkpoints.append({
                        'attempts': self.attempts,
                        'time': elapsed,
                        'rate': rate
                    })
                    print(f"[PROGRESS] Attempts: {self.attempts:,} | "
                          f"Elapsed: {elapsed:.2f}s | "
                          f"Rate: {rate:,.0f} attempts/sec | "
                          f"Last: '{guess}'")

                # Check if password matches
                if guess == self.password:
                    self.found = True
                    self.cracked_password = guess
                    break

            # Record attempts for this length
            self.length_attempts[length] = self.attempts - length_start

            if self.found:
                break

        self.end_time = time.time()
        return self.found

    def generate_report(self):
        """Generate comprehensive analysis report"""
        duration = self.end_time - self.start_time if self.end_time else 0
        rate = self.attempts / duration if duration > 0 else 0

        report = {
            'success': self.found,
            'password': self.cracked_password if self.found else None,
            'performance': {
                'total_attempts': self.attempts,
                'duration_seconds': round(duration, 3),
                'attempts_per_second': round(rate, 2),
                'efficiency_percentage': round((1 / self.attempts * 100) if self.attempts > 0 else 0, 6)
            },
            'search_strategy': {
                'max_length': self.max_length,
                'charset_size': len(self.charset),
                'attempts_by_length': self.length_attempts
            },
            'password_analysis': None,
            'timestamp': datetime.now().isoformat()
        }

        if self.found:
            report['password_analysis'] = self.analyze_password_complexity()

            # Calculate what percentage of search space was explored
            theoretical = self.estimate_theoretical_time()
            report['search_efficiency'] = {
                'combinations_tried': self.attempts,
                'total_search_space': theoretical['total_combinations'],
                'percentage_explored': round(self.attempts / theoretical['total_combinations'] * 100, 4)
            }

        return report

    def print_report(self):
        """Print formatted analysis report"""
        report = self.generate_report()

        print(f"\n{'='*70}")
        print(f"CRACK ATTEMPT RESULTS")
        print(f"{'='*70}\n")

        if report['success']:
            print(f"✓ [SUCCESS] Password Cracked: '{report['password']}'")
        else:
            print(f"✗ [FAILURE] Password not cracked within max length limit")

        print(f"\n{'─'*70}")
        print(f"PERFORMANCE METRICS")
        print(f"{'─'*70}")
        perf = report['performance']
        print(f"  Total Attempts:        {perf['total_attempts']:,}")
        print(f"  Duration:              {perf['duration_seconds']:.3f} seconds")
        print(f"  Attack Rate:           {perf['attempts_per_second']:,.2f} attempts/sec")
        print(f"  Efficiency:            {perf['efficiency_percentage']:.6f}%")

        print(f"\n{'─'*70}")
        print(f"SEARCH STRATEGY")
        print(f"{'─'*70}")
        strategy = report['search_strategy']
        print(f"  Max Password Length:   {strategy['max_length']}")
        print(f"  Character Set Size:    {strategy['charset_size']}")
        print(f"\n  Attempts per Length:")
        for length, attempts in sorted(strategy['attempts_by_length'].items()):
            print(f"    Length {length}: {attempts:,} attempts")

        if report['success']:
            print(f"\n{'─'*70}")
            print(f"PASSWORD COMPLEXITY ANALYSIS")
            print(f"{'─'*70}")
            analysis = report['password_analysis']
            print(f"  Password Length:       {analysis['length']}")
            print(f"  Unique Characters:     {analysis['unique_chars']}")
            print(f"  Character Types:       {analysis['character_types']}/4")
            print(f"    - Lowercase:         {'Yes' if analysis['has_lowercase'] else 'No'}")
            print(f"    - Uppercase:         {'Yes' if analysis['has_uppercase'] else 'No'}")
            print(f"    - Digits:            {'Yes' if analysis['has_digits'] else 'No'}")
            print(f"    - Special Chars:     {'Yes' if analysis['has_special'] else 'No'}")
            print(f"  Search Space:          {analysis['search_space']:,} combinations")
            print(f"  Exact Length Space:    {analysis['exact_length_space']:,} combinations")

            print(f"\n{'─'*70}")
            print(f"SEARCH EFFICIENCY")
            print(f"{'─'*70}")
            eff = report['search_efficiency']
            print(f"  Combinations Tried:    {eff['combinations_tried']:,}")
            print(f"  Total Search Space:    {eff['total_search_space']:,}")
            print(f"  Space Explored:        {eff['percentage_explored']:.4f}%")

        print(f"\n{'='*70}\n")

        return report

    def save_report(self, filename='crack_report.json'):
        """Save detailed report to JSON file"""
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[SAVED] Detailed report saved to {filename}")


def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("EDUCATIONAL PASSWORD CRACKER WITH DATA ANALYSIS")
    print("For authorized security testing and educational purposes only")
    print("="*70 + "\n")

    # Get password input
    password = input("Enter target password: ")

    # Configuration
    max_length = 6  # Increase for stronger passwords (warning: exponential growth)
    charset = string.ascii_letters + string.digits + string.punctuation

    # Initialize and run cracker
    cracker = PasswordCracker(
        password=password,
        max_length=max_length,
        charset=charset,
        verbose=True
    )

    # Execute attack
    cracker.crack()

    # Generate and display report
    cracker.print_report()

    # Optionally save report
    save = input("Save detailed report to JSON? (y/n): ").lower()
    if save == 'y':
        cracker.save_report()


if __name__ == "__main__":
    main()
