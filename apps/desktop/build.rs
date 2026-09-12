fn main() {
    slint_build::compile("../../crates/presentation/ui/app.slint")
        .expect("Slint UI konnte nicht kompiliert werden");
}
