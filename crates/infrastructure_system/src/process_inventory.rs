use sysinfo::System;

#[derive(Debug, Clone, Default)]
pub struct ProcessInventorySnapshot {
    pub total_count: usize,
    pub matched_count: usize,
    pub table: String,
}

pub fn read_process_inventory(
    query: &str,
    limit: usize,
) -> ProcessInventorySnapshot {
    let system = System::new_all();
    let normalized_query = query.trim().to_lowercase();

    let mut rows = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let pid_value = pid.as_u32();
            let name = process.name().to_string_lossy().into_owned();
            let path = process
                .exe()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "—".to_owned());

            let searchable = format!(
                "{} {} {}",
                pid_value,
                name,
                path,
            )
            .to_lowercase();

            if !normalized_query.is_empty()
                && !searchable.contains(&normalized_query)
            {
                return None;
            }

            Some((
                process.cpu_usage(),
                pid_value,
                name,
                process.memory(),
                path,
            ))
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        right
            .0
            .partial_cmp(&left.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.2.cmp(&right.2))
    });

    let total_count = system.processes().len();
    let matched_count = rows.len();
    let effective_limit = limit.max(1);

    let mut table = rows
        .iter()
        .take(effective_limit)
        .map(|(cpu, pid, name, memory, path)| {
            let memory_mb = *memory as f64 / 1024.0 / 1024.0;
            let short_name = truncate_text(name, 28);
            let short_path = truncate_text(path, 72);

            format!(
                "{} | {:>5.1}% | {:>7.1} MB | {}\n    {}",
                pid,
                cpu,
                memory_mb,
                short_name,
                short_path,
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    if table.is_empty() {
        table = if normalized_query.is_empty() {
            "KEINE PROZESSE VERFÜGBAR".to_owned()
        } else {
            "KEINE PASSENDEN PROZESSE GEFUNDEN".to_owned()
        };
    }

    let remaining = matched_count.saturating_sub(effective_limit);
    if remaining > 0 {
        table.push_str(&format!(
            "\n\n+ {} WEITERE TREFFER",
            remaining,
        ));
    }

    ProcessInventorySnapshot {
        total_count,
        matched_count,
        table,
    }
}

fn truncate_text(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_owned();
    }

    let keep = maximum.saturating_sub(3);
    let mut output = value.chars().take(keep).collect::<String>();
    output.push_str("...");
    output
}
