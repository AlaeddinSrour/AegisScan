// Static-analysis fixtures only; never execute or expose these handlers.
export function unsafeCatalog(req, res) {
  const fragment = req.query.filter
  return db.query(`SELECT sku FROM inventory WHERE category = '${fragment}'`)
}

export function boundCatalog(req, res) {
  return db.query('SELECT sku FROM inventory WHERE category = ?', {
    replacements: [req.query.filter]
  })
}

export function unsafeDocument(req, res) {
  return res.sendFile(req.params.document)
}

export function fixedDocument(req, res) {
  return res.sendFile('/srv/public/help.html')
}
