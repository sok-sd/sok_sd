use std::time::{Duration, Instant};
use crate::adapters::adapter::Adapter;

pub struct Benchmark {}

impl Benchmark {
    pub fn benchmark_function<F, T>(func: F, iterations: i8) -> Result<(Duration, T), String>
    where
        F: Fn() -> Result<T, String>
    {
        let mut start: Instant;
        let mut result = None;
        let mut total: f64 = 0f64;

        for _ in 0..iterations {
            start = Instant::now();
             if let Ok(inner) = func() {
                result = Some(inner)
            }

            total = total + start.elapsed().as_secs_f64();
        }

        let average_duration: Duration = Duration::from_secs_f64(total / (iterations as f64));
        match result {
            Some(result) => { Ok((average_duration, result)) },
            None => { Err("Function did not return a result".to_string()) }
        }
    }

    pub fn benchmark_initialization<F, T>(func: F, iterations: i8) -> Result<(Duration, Box<T>), String>
    where
        F: Fn() -> Result<T, String>,
        T: Adapter,
    {
        let (duration, result) = Benchmark::benchmark_function(func, iterations)?;
        Ok((duration, Box::new(result)))
    }
}