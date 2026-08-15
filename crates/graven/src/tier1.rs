use crate::error::{Error, Result};
use crate::store::CREATE_TIER1;
use bytes::Bytes;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::{Field, Row};
use rusqlite::Connection;

fn open_reader(parquet_bytes: &[u8]) -> Result<SerializedFileReader<Bytes>> {
    let bytes = Bytes::copy_from_slice(parquet_bytes);
    SerializedFileReader::new(bytes).map_err(|e| Error::Verify(format!("tier1 parquet: {e}")))
}

fn column_str<'a>(row: &'a Row, name: &str) -> Result<&'a str> {
    for (col_name, field) in row.get_column_iter() {
        if col_name == name {
            return match field {
                Field::Str(s) => Ok(s.as_str()),
                other => Err(Error::Verify(format!(
                    "tier1 column {name}: expected a UTF8 string, got {other}"
                ))),
            };
        }
    }
    Err(Error::Verify(format!(
        "tier1 parquet missing required column {name}"
    )))
}

fn column_i64(row: &Row, name: &str) -> Result<i64> {
    for (col_name, field) in row.get_column_iter() {
        if col_name == name {
            return match field {
                Field::Long(v) => Ok(*v),
                other => Err(Error::Verify(format!(
                    "tier1 column {name}: expected an int64, got {other}"
                ))),
            };
        }
    }
    Err(Error::Verify(format!(
        "tier1 parquet missing required column {name}"
    )))
}

pub fn import_extracts(conn: &Connection, parquet_bytes: &[u8]) -> Result<u64> {
    conn.execute_batch(CREATE_TIER1)?;
    let reader = open_reader(parquet_bytes)?;
    let mut count = 0u64;
    for row in reader
        .get_row_iter(None)
        .map_err(|e| Error::Verify(format!("tier1 extracts: {e}")))?
    {
        let row = row.map_err(|e| Error::Verify(format!("tier1 extracts: {e}")))?;
        let url = column_str(&row, "url")?.to_string();
        let publisher = column_str(&row, "publisher")?.to_string();
        let delta_id = column_str(&row, "delta_id")?.to_string();
        let extract = column_str(&row, "extract")?.to_string();
        conn.execute(
            "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(url, publisher) DO UPDATE SET delta_id = excluded.delta_id, extract = excluded.extract",
            (&url, &publisher, &delta_id, &extract),
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn import_links(conn: &Connection, parquet_bytes: &[u8]) -> Result<u64> {
    conn.execute_batch(CREATE_TIER1)?;
    let reader = open_reader(parquet_bytes)?;
    let mut count = 0u64;
    for row in reader
        .get_row_iter(None)
        .map_err(|e| Error::Verify(format!("tier1 links: {e}")))?
    {
        let row = row.map_err(|e| Error::Verify(format!("tier1 links: {e}")))?;
        let source_url = column_str(&row, "source_url")?.to_string();
        let target_url = column_str(&row, "target_url")?.to_string();
        let position = column_i64(&row, "position")?;
        conn.execute(
            "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
            (&source_url, &target_url, position),
        )?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;
    use std::sync::Arc;

    fn write_parquet(
        message_type: &str,
        byte_columns: &[Vec<Vec<u8>>],
        int_column: Option<&[i64]>,
    ) -> Vec<u8> {
        let schema = Arc::new(parse_message_type(message_type).unwrap());
        let mut writer = SerializedFileWriter::new(
            Vec::new(),
            schema,
            Arc::new(WriterProperties::builder().build()),
        )
        .unwrap();
        let mut rg = writer.next_row_group().unwrap();
        for column in byte_columns {
            let mut col = rg.next_column().unwrap().unwrap();
            let values: Vec<ByteArray> =
                column.iter().map(|v| ByteArray::from(v.clone())).collect();
            col.typed::<ByteArrayType>()
                .write_batch(&values, None, None)
                .unwrap();
            col.close().unwrap();
        }
        if let Some(ints) = int_column {
            let mut col = rg.next_column().unwrap().unwrap();
            col.typed::<Int64Type>()
                .write_batch(ints, None, None)
                .unwrap();
            col.close().unwrap();
        }
        rg.close().unwrap();
        writer.into_inner().unwrap()
    }

    fn write_extracts_parquet(rows: &[(&str, &str, &str, &str)]) -> Vec<u8> {
        write_parquet(
            "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary delta_id (UTF8); required binary extract (UTF8); }",
            &[
                rows.iter().map(|r| r.0.as_bytes().to_vec()).collect(),
                rows.iter().map(|r| r.1.as_bytes().to_vec()).collect(),
                rows.iter().map(|r| r.2.as_bytes().to_vec()).collect(),
                rows.iter().map(|r| r.3.as_bytes().to_vec()).collect(),
            ],
            None,
        )
    }

    fn write_links_parquet(rows: &[(&str, &str, i64)]) -> Vec<u8> {
        write_parquet(
            "message links { required binary source_url (UTF8); required binary target_url (UTF8); required int64 position; }",
            &[
                rows.iter().map(|r| r.0.as_bytes().to_vec()).collect(),
                rows.iter().map(|r| r.1.as_bytes().to_vec()).collect(),
            ],
            Some(&rows.iter().map(|r| r.2).collect::<Vec<_>>()),
        )
    }

    #[test]
    fn import_extracts_round_trips_rows() {
        let bytes = write_extracts_parquet(&[
            (
                "https://a.example/x",
                "a.example",
                "sha256:1",
                "extract one",
            ),
            (
                "https://a.example/y",
                "a.example",
                "sha256:2",
                "extract two",
            ),
        ]);
        let conn = Connection::open_in_memory().unwrap();
        let count = import_extracts(&conn, &bytes).unwrap();
        assert_eq!(count, 2);

        let extract: String = conn
            .query_row(
                "SELECT extract FROM extracts WHERE url = ?1",
                ["https://a.example/x"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(extract, "extract one");

        conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )
        .unwrap();
        let fts_hit: String = conn
            .query_row(
                "SELECT extract FROM extracts_fts WHERE extracts_fts MATCH 'two'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fts_hit, "extract two");
    }

    #[test]
    fn import_extracts_ignores_unknown_extra_column() {
        let bytes = write_parquet(
            "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary delta_id (UTF8); required binary extract (UTF8); required binary embedding_hint (UTF8); }",
            &[
                vec![b"https://a.example/x".to_vec()],
                vec![b"a.example".to_vec()],
                vec![b"sha256:1".to_vec()],
                vec![b"extract one".to_vec()],
                vec![b"unused".to_vec()],
            ],
            None,
        );
        let conn = Connection::open_in_memory().unwrap();
        let count = import_extracts(&conn, &bytes).unwrap();
        assert_eq!(count, 1);
        let extract: String = conn
            .query_row("SELECT extract FROM extracts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(extract, "extract one");
    }

    #[test]
    fn import_extracts_errors_when_extract_column_missing() {
        let bytes = write_parquet(
            "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary delta_id (UTF8); }",
            &[
                vec![b"https://a.example/x".to_vec()],
                vec![b"a.example".to_vec()],
                vec![b"sha256:1".to_vec()],
            ],
            None,
        );
        let conn = Connection::open_in_memory().unwrap();
        let err = import_extracts(&conn, &bytes).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }

    #[test]
    fn import_links_round_trips_rows() {
        let bytes = write_links_parquet(&[
            ("https://a.example/x", "https://a.example/y", 0),
            ("https://a.example/x", "https://a.example/z", 1),
        ]);
        let conn = Connection::open_in_memory().unwrap();
        let count = import_links(&conn, &bytes).unwrap();
        assert_eq!(count, 2);

        let target: String = conn
            .query_row("SELECT target_url FROM links WHERE position = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(target, "https://a.example/z");
    }

    #[test]
    fn import_links_errors_when_position_column_missing() {
        let bytes = write_parquet(
            "message links { required binary source_url (UTF8); required binary target_url (UTF8); }",
            &[
                vec![b"https://a.example/x".to_vec()],
                vec![b"https://a.example/y".to_vec()],
            ],
            None,
        );
        let conn = Connection::open_in_memory().unwrap();
        let err = import_links(&conn, &bytes).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }
}
