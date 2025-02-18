use serde_json::{Map, Value};
use crate::adapters::adapter::Adapter;
use crate::benchmark::Benchmark;

pub enum Display {
    DisplayJWT,
    DisplayFancyStats,
}

impl Display {
    pub fn display(&self, sd_algorithms: &Vec<Box<dyn Adapter>>, raw_vc: &Map<String, Value>, disclosures: &Vec<String>, iterations: i8) -> Result<(), String> {
        match self {
            Display::DisplayJWT => { DisplayJWT::display(sd_algorithms, raw_vc, disclosures, iterations) }
            Display::DisplayFancyStats => { DisplayFancyStats::display(sd_algorithms, raw_vc, disclosures, iterations) }
        }
    }

}

pub trait DisplayData {
    fn display(sd_algorithms: &Vec<Box<dyn Adapter>>, raw_vc: &Map<String, Value>, disclosures: &Vec<String>, iterations: i8) -> Result<(), String>;
}

struct DisplayJWT {}
impl DisplayData for DisplayJWT {
    fn display(sd_algorithms: &Vec<Box<dyn Adapter>>, raw_vc: &Map<String, Value>, disclosures: &Vec<String>, _iterations: i8) -> Result<(), String> {
        for adapter in sd_algorithms {
            let raw_vc_copy: &mut Map<String, Value> = &mut raw_vc.clone();

            let (vc, _jwt) = adapter.issue_vc(raw_vc_copy)?;
            adapter.verify_vc(&vc)?;
            let vc_json = serde_json::to_string_pretty(&Value::Object(vc.clone())).unwrap();
            println!("{:10} VC = {}\n", adapter.sd_algorithm(), vc_json);

            let (vp, vp_jwt) = adapter.issue_vp(&vc, &disclosures)?;
            adapter.verify_vp(&vp_jwt)?;
            let vp_json = serde_json::to_string_pretty(&Value::Object(vp.clone())).unwrap();

            println!("{:10} VP = {}\n", adapter.sd_algorithm(), vp_json);
        }

        Ok(())
    }
}

struct DisplayFancyStats {}
impl DisplayData for DisplayFancyStats {
    fn display(sd_algorithms: &Vec<Box<dyn Adapter>>, raw_vc: &Map<String, Value>, disclosures: &Vec<String>, iterations: i8) -> Result<(), String> {
        for adapter in sd_algorithms {

            let raw_vc_copy: &mut Map<String, Value> = &mut raw_vc.clone();

            let (elapsed, (vc, jwt)) = Benchmark::benchmark_function(|| adapter.issue_vc(raw_vc_copy), iterations)?;

            println!();
            println!("            ╔════════════════════════════╗           ");
            println!("            ║ {:^26} ║ ", adapter.sd_algorithm());
            println!("╔═══════════╩══════════════╦═════════════╩═════════╗");
            println!("║ - VC Issuance Time:      ║ {:>18} ns ║", elapsed.as_nanos());
            println!("║ - VC Encoded Length:     ║ {:>18}  B ║", jwt.len());

            let (elapsed, _) = Benchmark::benchmark_function(|| adapter.verify_vc(&vc), iterations)?;

            println!("║ - VC Verification Time:  ║ {:>18} ns ║", elapsed.as_nanos());
            println!("╠══════════════════════════╦═══════════════════════╣");

            let (elapsed, (_vp, vp_jwt)) = Benchmark::benchmark_function(|| adapter.issue_vp(&vc, &disclosures), iterations)?;

            println!("║ - VP Issuance Time:      ║ {:>18} ns ║", elapsed.as_nanos());
            println!("║ - VP Encoded Length:     ║ {:>18}  B ║", vp_jwt.len());

            let (elapsed, _) = Benchmark::benchmark_function(|| adapter.verify_vp(&vp_jwt), iterations)?;

            println!("║ - VP Verification Time:  ║ {:>18} ns ║", elapsed.as_nanos());
            println!("╚══════════════════════════╩═══════════════════════╝\n");

        }

        Ok(())
    }
}