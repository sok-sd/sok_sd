pub struct Utils {}

impl Utils {
    pub fn complementary_indices(disclosed_indices: Vec<usize>, len: usize) -> Vec<usize> {
        let mut undisclosed_indices: Vec<usize> = vec![];

        for index in 0..len {
            if !disclosed_indices.contains(&index) {
                undisclosed_indices.push(index);
            }
        }

        undisclosed_indices
    }
}
