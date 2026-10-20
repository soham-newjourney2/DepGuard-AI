const express = require('express');

const app = express();
app.use(express.json());

app.get('/search', (req, res) => {
  const { q = '', tags = [] } = req.query;
  res.json({ q, tags: [].concat(tags) });
});

app.post('/echo', (req, res) => res.json({ received: req.body }));

module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`vuln-demo listening on ${port}`));
}
