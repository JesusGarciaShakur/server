const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    organizer: {
      type: String,
      required: true,
    },
    guests: {
      type: Array,
      required: true,
    },
    address: {
      type: String,
      required: true,
    },
    city: {
      type: String,
      required: true,
    },
    pincode: {
      type: Number,
      required: true,
    },
    date: {
      type: String,
      required: true,
    },
    time: {
      type: String,
      required: true,
    },
    media: {
      type: Array,
      required: false,
      default: [],
    },
    ticketTypes: {
      type: Array,
      required: false,
      default: [],
    },
  },
  { timestamps: true }
);

const EventModel = mongoose.model("events", eventSchema);
module.exports = EventModel;
