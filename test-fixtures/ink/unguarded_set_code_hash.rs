// Test fixture for INK-011: unguarded-set-code-hash
// set_code_hash usage without admin/owner verification

impl MyContract {
    pub fn upgrade(&mut self, new_code_hash: Hash) {
        self.env().set_code_hash(&new_code_hash).expect("upgrade failed");
    }

    pub fn migrate_code(&mut self, code_hash: Hash) {
        self.env().set_code_hash(&code_hash).unwrap();
        self.version += 1;
    }
}
