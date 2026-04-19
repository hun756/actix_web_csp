use actix_web_csp::{preset_policy, CspPolicy, CspPreset};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let preset = CspPreset::try_from("dashboard")?;
    let policy = preset_policy(preset);
    let json = policy.to_json_pretty()?;
    let round_tripped = CspPolicy::from_json_str(&json)?;
    let compiled = round_tripped.compile()?;

    println!("Preset walkthrough");
    println!("Preset name : {}", preset);
    println!("JSON export :\n{json}");
    println!("Round trip header: {}", compiled.header_value().to_str()?);

    Ok(())
}
