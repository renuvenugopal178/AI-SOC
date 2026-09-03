import mongoose from 'mongoose';
import Alert, { AlertSeverity, IAlert } from '../models/Alert';
import Incident, { IncidentSeverity, IIncident } from '../models/Incident';

const DEFAULT_WINDOW_MINUTES = 30;
const severityRank: Record<AlertSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const getWindowMinutes = (): number => {
  const configured = Number(process.env.INCIDENT_CORRELATION_WINDOW_MINUTES);
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_WINDOW_MINUTES;
};

const getIncidentSeverity = (alerts: IAlert[]): IncidentSeverity => {
  return alerts.reduce<AlertSeverity>((highest, alert) => (
    severityRank[alert.severity] > severityRank[highest] ? alert.severity : highest
  ), 'LOW');
};

const calculateRiskScore = (alerts: IAlert[]): number => {
  const total = alerts.reduce((sum, alert) => sum + Math.max(0, Math.min(100, alert.riskScore)), 0);
  return Math.min(100, total);
};

const incidentDescription = (alerts: IAlert[]): string => {
  const eventTypes = [...new Set(alerts.map((alert) => alert.eventType).filter(Boolean))];
  return `Correlated security alerts from the same source IP${eventTypes.length ? ` involving ${eventTypes.join(', ')}` : ''}.`;
};

export const correlateAlert = async (alert: IAlert): Promise<IIncident | null> => {
  if (!alert.sourceIp || !alert.triggeredAt) {
    return null;
  }

  const windowMilliseconds = getWindowMinutes() * 60 * 1000;
  const cutoff = new Date(alert.triggeredAt.getTime() - windowMilliseconds);
  const relatedAlerts = await Alert.find({
    sourceIp: alert.sourceIp,
    triggeredAt: { $gte: cutoff, $lte: alert.triggeredAt },
  }).sort({ triggeredAt: 1, createdAt: 1 });

  if (relatedAlerts.length < 2) {
    return null;
  }

  const relatedEventIds = relatedAlerts.map((relatedAlert) => relatedAlert.eventId);
  const sourceIps = [...new Set(relatedAlerts.map((relatedAlert) => relatedAlert.sourceIp).filter((ip): ip is string => Boolean(ip)))];
  const affectedUsers = [...new Set(relatedAlerts.map((relatedAlert) => relatedAlert.username).filter((username): username is string => Boolean(username)))];
  const firstSeen = relatedAlerts.reduce((earliest, relatedAlert) => (
    relatedAlert.triggeredAt < earliest ? relatedAlert.triggeredAt : earliest
  ), relatedAlerts[0].triggeredAt);
  const lastSeen = relatedAlerts.reduce((latest, relatedAlert) => (
    relatedAlert.triggeredAt > latest ? relatedAlert.triggeredAt : latest
  ), relatedAlerts[0].triggeredAt);
  const severity = getIncidentSeverity(relatedAlerts);
  const riskScore = calculateRiskScore(relatedAlerts);

  let incident = await Incident.findOne({
    sourceIps: alert.sourceIp,
    lastSeen: { $gte: cutoff },
    status: { $nin: ['RESOLVED', 'FALSE_POSITIVE'] },
  });

  if (!incident) {
    incident = await Incident.create({
      incidentId: `INC-${new Date().getTime()}-${new mongoose.Types.ObjectId().toString().slice(-6)}`,
      title: 'Correlated security activity detected',
      description: incidentDescription(relatedAlerts),
      severity,
      riskScore,
      status: 'NEW',
      sourceIps,
      affectedUsers,
      relatedEventIds,
      relatedAlertIds: relatedAlerts.map((relatedAlert) => relatedAlert._id),
      firstSeen,
      lastSeen,
    });
    return incident;
  }

  incident.sourceIps = sourceIps;
  incident.affectedUsers = affectedUsers;
  incident.relatedEventIds = relatedEventIds;
  incident.relatedAlertIds = relatedAlerts.map((relatedAlert) => relatedAlert._id);
  incident.firstSeen = firstSeen < incident.firstSeen ? firstSeen : incident.firstSeen;
  incident.lastSeen = lastSeen > incident.lastSeen ? lastSeen : incident.lastSeen;
  incident.severity = severity;
  incident.riskScore = riskScore;
  incident.description = incidentDescription(relatedAlerts);
  await incident.save();

  return incident;
};

export default { correlateAlert };
