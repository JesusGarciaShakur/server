const express = require("express");
const router = express.Router();
const validateToken = require("../middlewares/validate-token");
const EventModel = require("../models/event-model");

router.post("/create-event", validateToken, async (req, res) => {
  try {
    const event = await EventModel.create(req.body);
    return res
      .status(201)
      .json({ message: "Evento creado con éxito", event });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.put("/edit-event/:id", validateToken, async (req, res) => {
  try {
    const event = await EventModel.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    return res.json({ message: "Evento actualizado con éxito", event });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.delete("/delete-event/:id", validateToken, async (req, res) => {
  try {
    await EventModel.findByIdAndDelete(req.params.id);
    return res.json({ message: "Evento eliminado con éxito" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.get("/get-events", validateToken, async (req, res) => {
  try {
    // access search query
    const searchText = req.query.searchText;
    const date = req.query.date;

    const events = await EventModel.find({
      name: { $regex: new RegExp(searchText, "i") },
      ...(date && { date }),
    }).sort({ createdAt: -1 });
    return res.json({ data: events });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.get("/get-event/:id", validateToken, async (req, res) => {
  try {
    const event = await EventModel.findById(req.params.id);
    return res.json({ data: event });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

module.exports = router;
