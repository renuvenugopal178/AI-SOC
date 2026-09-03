import mongoose, { Document, Model, Schema } from 'mongoose';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface IIncident extends Document {
  incidentId: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  riskScore: number;
  status: IncidentStatus;
  sourceIps: string[];
  affectedUsers: string[];
  relatedEventIds: mongoose.Types.ObjectId[];
  relatedAlertIds: mongoose.Types.ObjectId[];
  firstSeen: Date;
  lastSeen: Date;
  createdAt: Date;
  updatedAt: Date;
}

const incidentSchema = new Schema<IIncident>(
  {
    incidentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 256,
    },
    description: {
      type: String,
      required: true,
      trim: true,
      maxlength: 2000,
    },
    severity: {
      type: String,
      required: true,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      index: true,
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      index: true,
    },
    status: {
      type: String,
      required: true,
      enum: ['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
      default: 'NEW',
      index: true,
    },
    sourceIps: {
      type: [String],
      default: [],
      index: true,
    },
    affectedUsers: {
      type: [String],
      default: [],
    },
    relatedEventIds: {
      type: [Schema.Types.ObjectId],
      ref: 'SecurityEvent',
      default: [],
    },
    relatedAlertIds: {
      type: [Schema.Types.ObjectId],
      ref: 'Alert',
      default: [],
    },
    firstSeen: {
      type: Date,
      required: true,
      index: true,
    },
    lastSeen: {
      type: Date,
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

incidentSchema.index({ sourceIps: 1, lastSeen: -1 });

const Incident: Model<IIncident> = mongoose.model<IIncident>('Incident', incidentSchema);

export default Incident;
