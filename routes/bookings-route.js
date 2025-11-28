const express = require("express");
const router = express.Router();
const validateToken = require("../middlewares/validate-token");
const sendEmail = require("../helpers/send-email");
const BookingModel = require("../models/booking-model");
const EventModel = require("../models/event-model");
const UserModel = require("../models/user-model");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

router.post("/create-booking", validateToken, async (req, res) => {
  try {
    req.body.user = req.user._id;

    // create booking
    const booking = await BookingModel.create(req.body);

    // update event tickets
    const event = await EventModel.findById(req.body.event);
    const ticketTypes = event.ticketTypes;
    const updatedTicketTypes = ticketTypes.map((ticketType) => {
      if (ticketType.name === req.body.ticketType) {
        ticketType.booked =
          Number(ticketType.booked ?? 0) + Number(req.body.ticketsCount);
        ticketType.available =
          Number(ticketType.available ?? ticketType.limit) -
          Number(req.body.ticketsCount);
      }

      return ticketType;
    });

    await EventModel.findByIdAndUpdate(req.body.event, {
      ticketTypes: updatedTicketTypes,
    });

    // send email
    const userObj = await UserModel.findById(req.user._id);
    const emailPayload = {
      email: userObj.email,
      subject: "Confirmación de reserva - Groovix",
      text: `Has reservado con éxito ${req.body.ticketsCount} boleto(s) para ${event.name}.`,
      html: ``,
    };

    await sendEmail(emailPayload);

    return res
      .status(201)
      .json({ message: "Reserva creada con éxito", booking });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.get("/get-user-bookings", validateToken, async (req, res) => {
  try {
    const bookings = await BookingModel.find({ user: req.user._id })
      .populate("event")
      .sort({ createdAt: -1 });

    return res.status(200).json({ data: bookings });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.get("/get-all-bookings", validateToken, async (req, res) => {
  try {
    const bookings = await BookingModel.find()
      .populate("event")
      .populate("user")
      .sort({ createdAt: -1 });

    return res.status(200).json({ data: bookings });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

router.post("/cancel-booking", validateToken, async (req, res) => {
  try {
    const { eventId, paymentId, bookingId, ticketsCount, ticketTypeName } =
      req.body;

    const refund = await stripe.refunds.create({
      payment_intent: paymentId,
    });

    if (refund.status === "succeeded") {
      await BookingModel.findByIdAndUpdate(bookingId, { status: "cancelled" });

      // update event tickets
      const event = await EventModel.findById(eventId);
      const ticketTypes = event.ticketTypes;
      const updatedTicketTypes = ticketTypes.map((ticketType) => {
        if (ticketType.name === ticketTypeName) {
          ticketType.booked =
            Number(ticketType.booked ?? 0) - Number(ticketsCount);
          ticketType.available =
            Number(ticketType.available ?? ticketType.limit) +
            Number(ticketsCount);
        }

        return ticketType;
      });

      await EventModel.findByIdAndUpdate(eventId, {
        ticketTypes: updatedTicketTypes,
      });

      const userObj = await UserModel.findById(req.user._id);
      const emailPayload = {
        email: userObj.email,
        subject: "Cancelación de reserva - Groovix",
        text: `Has cancelado con éxito tu reserva para ${event.name}.`,
        html: ``,
      };

      await sendEmail(emailPayload);

      return res.status(200).json({ message: "Evento cancelado exitosamente" });
    } else {
      return res.status(400).json({ message: "Reembolso fallido" });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

module.exports = router;
