const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const pool = new Pool({
  user: "username",
  host: "localhost",
  database: "store",
  password: "password",
  port: 5432,
});

const secretKey = "your-secret-key"; // Use a more secure key in production

// Register
app.post("/api/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *",
      [username, hashedPassword, role]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (user.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const isValid = await bcrypt.compare(password, user.rows[0].password);

    if (!isValid) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role }, secretKey);
    res.json({ token, role: user.rows[0].role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(500).json({ error: "Failed to authenticate token" });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// Add product (Seller only)
app.post("/api/products", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id, item_name, item_quantity, item_price } = req.body;
  try {
    const existingProduct = await pool.query("SELECT * FROM products WHERE item_id = $1", [
      item_id,
    ]);

    if (existingProduct.rows.length > 0) {
      return res.status(400).json({ error: "Product with this ID already exists" });
    }

    const result = await pool.query(
      "INSERT INTO products (item_id, item_name, item_quantity, item_price) VALUES ($1, $2, $3, $4) RETURNING *",
      [item_id, item_name, item_quantity, item_price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// View products (Seller and Customer)
app.get("/api/products", authenticate, async (req, res) => {
  if (req.userRole !== "seller" && req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  try {
    const result = await pool.query("SELECT * FROM products");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// server.js (update these endpoints)
app.put("/api/products/:id/price", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  const { newPrice } = req.body;
  try {
    await pool.query("UPDATE products SET item_price = $1 WHERE id = $2", [newPrice, id]);
    res.json({ message: "Product price updated successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/products/:id/quantity", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  const { newQuantity } = req.body;
  try {
    await pool.query("UPDATE products SET item_quantity = item_quantity + $1 WHERE id = $2", [newQuantity, id]);
    res.json({ message: "Product quantity updated successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/products/:id", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM products WHERE id = $1", [id]);
    res.json({ message: "Product removed successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Buy product (Customer only)
app.post("/api/buy", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id, quantity } = req.body;
  try {
    const product = await pool.query("SELECT * FROM products WHERE item_id = $1", [
      item_id,
    ]);
    if (product.rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    if (product.rows[0].item_quantity < quantity) {
      return res.status(400).json({ error: "Insufficient quantity" });
    }
    const updatedProduct = await pool.query(
      "UPDATE products SET item_quantity = item_quantity - $1 WHERE item_id = $2 RETURNING *",
      [quantity, item_id]
    );
    res.json(updatedProduct.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete product (Customer only)
app.delete("/api/buy/:item_id", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id } = req.params;
  try {
    const product = await pool.query("SELECT * FROM products WHERE item_id = $1", [
      item_id,
    ]);
    if (product.rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    await pool.query("DELETE FROM products WHERE item_id = $1", [item_id]);
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generate bill (Customer only)
app.post("/api/generate-bill", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { selectedItems } = req.body;
  let totalAmount = 0;

  try {
    for (const item of selectedItems) {
      const product = await pool.query("SELECT * FROM products WHERE item_id = $1", [
        item.item_id,
      ]);
      if (product.rows.length === 0) {
        return res.status(404).json({ error: `Product ${item.item_id} not found` });
      }
      if (product.rows[0].item_quantity < item.quantity) {
        return res.status(400).json({ error: `Insufficient quantity for product ${item.item_id}` });
      }

      // Update inventory
      const newQuantity = product.rows[0].item_quantity - item.quantity;
      if (newQuantity === 0) {
        // Delete product if quantity is zero
        await pool.query("DELETE FROM products WHERE item_id = $1", [item.item_id]);
      } else {
        // Update product quantity
        await pool.query(
          "UPDATE products SET item_quantity = $1 WHERE item_id = $2",
          [newQuantity, item.item_id]
        );
      }

      totalAmount += product.rows[0].item_price * item.quantity;
    }
    res.json({ totalAmount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(5001, () => {
  console.log("Server running on http://localhost:5001");
});
