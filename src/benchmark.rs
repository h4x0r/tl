//! Performance benchmarking and profiling utilities

use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Performance metrics tracker
#[derive(Debug)]
pub struct PerformanceMetrics {
    timings: HashMap<String, Vec<Duration>>,
    memory_usage: HashMap<String, usize>,
    counters: HashMap<String, usize>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            timings: HashMap::new(),
            memory_usage: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    /// Record timing for an operation
    pub fn record_timing(&mut self, operation: &str, duration: Duration) {
        self.timings.entry(operation.to_string()).or_default().push(duration);
    }

    /// Record memory usage for an operation
    pub fn record_memory(&mut self, operation: &str, bytes: usize) {
        self.memory_usage.insert(operation.to_string(), bytes);
    }

    /// Increment counter
    pub fn increment_counter(&mut self, counter: &str) {
        *self.counters.entry(counter.to_string()).or_insert(0) += 1;
    }

    /// Get average timing for an operation
    pub fn avg_timing(&self, operation: &str) -> Option<Duration> {
        self.timings.get(operation).map(|times| {
            let total: Duration = times.iter().sum();
            total / times.len() as u32
        })
    }

    /// Print performance summary
    pub fn print_summary(&self) {
        println!("\n📊 Performance Summary:");
        println!("======================");
        
        // Timings
        if !self.timings.is_empty() {
            println!("\n⏱️  Timing Metrics:");
            for (operation, times) in &self.timings {
                let avg = times.iter().sum::<Duration>() / times.len() as u32;
                let min = times.iter().min().unwrap();
                let max = times.iter().max().unwrap();
                println!("  {}: avg={:.2}ms, min={:.2}ms, max={:.2}ms (n={})",
                    operation,
                    avg.as_secs_f64() * 1000.0,
                    min.as_secs_f64() * 1000.0,
                    max.as_secs_f64() * 1000.0,
                    times.len()
                );
            }
        }

        // Memory usage
        if !self.memory_usage.is_empty() {
            println!("\n💾 Memory Usage:");
            for (operation, bytes) in &self.memory_usage {
                println!("  {}: {:.2} MB", operation, *bytes as f64 / 1_048_576.0);
            }
        }

        // Counters
        if !self.counters.is_empty() {
            println!("\n🔢 Counters:");
            for (counter, count) in &self.counters {
                println!("  {}: {}", counter, count);
            }
        }
    }
}

/// Timer for measuring operation performance
pub struct Timer {
    start: Instant,
    operation: String,
    metrics: Option<std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>>,
}

impl Timer {
    pub fn new(operation: &str) -> Self {
        Self {
            start: Instant::now(),
            operation: operation.to_string(),
            metrics: None,
        }
    }

    pub fn with_metrics(operation: &str, metrics: std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>) -> Self {
        Self {
            start: Instant::now(),
            operation: operation.to_string(),
            metrics: Some(metrics),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn stop(self) -> Duration {
        let elapsed = self.elapsed();
        if let Some(metrics) = self.metrics {
            if let Ok(mut m) = metrics.lock() {
                m.record_timing(&self.operation, elapsed);
            }
        }
        elapsed
    }
}

/// Macro for easy timing
#[macro_export]
macro_rules! time_operation {
    ($metrics:expr, $operation:expr, $code:block) => {{
        let timer = crate::benchmark::Timer::with_metrics($operation, $metrics.clone());
        let result = $code;
        timer.stop();
        result
    }};
}

/// Memory usage tracker
pub struct MemoryTracker {
    initial_usage: usize,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            initial_usage: Self::get_memory_usage(),
        }
    }

    pub fn current_usage(&self) -> usize {
        Self::get_memory_usage()
    }

    pub fn delta(&self) -> isize {
        Self::get_memory_usage() as isize - self.initial_usage as isize
    }

    #[cfg(unix)]
    fn get_memory_usage() -> usize {
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<usize>() {
                            return kb * 1024; // Convert KB to bytes
                        }
                    }
                }
            }
        }
        0
    }

    #[cfg(not(unix))]
    fn get_memory_usage() -> usize {
        // Fallback for non-Unix systems
        0
    }
}

/// Benchmark suite for MFT parsing performance
pub struct MftBenchmark {
    pub metrics: std::sync::Arc<std::sync::Mutex<PerformanceMetrics>>,
}

impl MftBenchmark {
    pub fn new() -> Self {
        Self {
            metrics: std::sync::Arc::new(std::sync::Mutex::new(PerformanceMetrics::new())),
        }
    }

    /// Benchmark MFT parsing with different implementations
    pub fn benchmark_parsing(&self, data: &[u8]) -> Result<(), crate::error::Error> {
        println!("🚀 Starting MFT parsing benchmarks...");

        // Benchmark original parser
        {
            let mut parser = crate::mft::MftParser::new();
            let timer = Timer::with_metrics("original_parser", self.metrics.clone());
            let memory_tracker = MemoryTracker::new();
            
            let _records = parser.parse_mft_data(data)?;
            
            timer.stop();
            if let Ok(mut m) = self.metrics.lock() {
                m.record_memory("original_parser_memory", memory_tracker.delta().max(0) as usize);
            }
        }

        // Benchmark optimized parser
        {
            let mut parser = crate::mft::MftParser::new();
            let timer = Timer::with_metrics("optimized_parser", self.metrics.clone());
            let memory_tracker = MemoryTracker::new();
            
            let _records = parser.parse_mft_data(data)?;
            
            timer.stop();
            if let Ok(mut m) = self.metrics.lock() {
                m.record_memory("optimized_parser_memory", memory_tracker.delta().max(0) as usize);
            }
        }

        Ok(())
    }

    /// Calculate speedup ratio
    pub fn calculate_speedup(&self) -> Option<f64> {
        if let Ok(metrics) = self.metrics.lock() {
            let original_time = metrics.avg_timing("original_parser")?;
            let optimized_time = metrics.avg_timing("optimized_parser")?;
            
            Some(original_time.as_secs_f64() / optimized_time.as_secs_f64())
        } else {
            None
        }
    }

    /// Print benchmark results
    pub fn print_results(&self) {
        if let Ok(metrics) = self.metrics.lock() {
            metrics.print_summary();
            
            if let Some(speedup) = self.calculate_speedup() {
                println!("\n🎯 Optimization Results:");
                println!("  Speedup: {:.2}x faster", speedup);
                
                if speedup > 1.5 {
                    println!("  ✅ Significant performance improvement!");
                } else if speedup > 1.1 {
                    println!("  ✅ Moderate performance improvement");
                } else {
                    println!("  ⚠️  Minimal performance difference");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_timer() {
        let timer = Timer::new("test_operation");
        thread::sleep(Duration::from_millis(10));
        let elapsed = timer.stop();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_metrics() {
        let mut metrics = PerformanceMetrics::new();
        metrics.record_timing("test", Duration::from_millis(100));
        metrics.record_timing("test", Duration::from_millis(200));
        
        let avg = metrics.avg_timing("test").unwrap();
        assert_eq!(avg, Duration::from_millis(150));
    }

    #[test]
    fn test_memory_tracker() {
        let tracker = MemoryTracker::new();
        let _usage = tracker.current_usage();
        let _delta = tracker.delta();
        // Just ensure it doesn't panic
    }
}