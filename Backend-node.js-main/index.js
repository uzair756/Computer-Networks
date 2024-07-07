const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/contact');
const reservationSchema = new mongoose.Schema({
  name: String,
  email: String,
  subject: String,
  date: Date,
  weekday: String,
  dayslot: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Reservation = mongoose.model('Reservation', reservationSchema);

app.post('/send', async (req, res) => {
  try {
    const reservation = new Reservation(req.body);
    const result = await reservation.save();
    console.log(result);
    res.status(201).send("Lab reserved successfully!");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error saving reservation data");
  }
});

app.listen(3006, () => {
  console.log("Server is running on port 3006");
});
