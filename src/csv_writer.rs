use std::collections::HashMap;
use std::fs::{File, metadata};
use std::fs::create_dir;
use std::path::Path;
use csv::Writer;
use serde::Serialize;

pub struct CSVWriter {
    columns: Vec<String>,
    writers: HashMap<String, Writer<File>>,
}
const CSV_DIR: &str = "./csv_dir";
const CSV_EXT: &str = ".csv";

impl CSVWriter {

    fn check_dir_existence_or_create(csv_dir: &Path) -> Result<(), String> {

        if ! metadata(csv_dir).is_ok() {            // directory does not exist
            match create_dir(csv_dir) {
                Ok(_) => {}
                Err(err) => { return Err(format!("Error in creating CSV folder: [{err}]")) }
            };
        }
        Ok(())
    }
    pub fn new(columns: Vec<String>) -> Result<Self, String> {

        let csv_dir: &Path = Path::new(CSV_DIR);
        Self::check_dir_existence_or_create(csv_dir)?;

        Ok(CSVWriter { columns, writers: HashMap::new() })
    }

    pub fn add_writer(&mut self, filename: &String) -> Result<(), String> {

        let mut filename_with_extension: String = filename.clone();
        filename_with_extension.push_str(CSV_EXT);

        let csv_dir: &Path = Path::new(CSV_DIR);
        Self::check_dir_existence_or_create(csv_dir)?;
        let full_path = csv_dir.join(filename_with_extension);

        let file = match File::create(full_path) {
            Ok(file) => { file }
            Err(err) => { return Err(format!("Error in creating file for CSV Writer: [{err}]")) }
        };

        let writer = Writer::from_writer(file);
        match self.writers.insert(filename.clone(), writer) {
            None => { }
            Some(_) => { return Err(format!("HashMap already has a writer for {filename} key"))}
        };

        self.serialize_record(filename, self.columns.clone())?;

        Ok(())
    }

    pub fn serialize_record<S: Serialize + std::fmt::Debug>(&mut self, filename: &String, record: S) -> Result<(), String>
    {
        let writer: &mut Writer<File> = match self.writers.get_mut(filename) {
            None => { return Err(format!("Filename {filename} was not found in map"))}
            Some(writer) => { writer }
        };

        match writer.serialize(record) {
            Ok(_) => { Ok(()) }
            Err(err) => { Err(format!("Error in writing record: [{err}]")) }
        }

    }

    pub fn flush_all(&mut self) -> Result<(), String> {

        for (filename, writer) in self.writers.iter_mut() {
            match writer.flush() {
                Ok(_) => { }
                Err(err) => { return Err(format!("Could not flush writer \"{filename}\": [{err}"))}
            };
        }

        Ok(())
    }
}