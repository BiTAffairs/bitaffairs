// Maps the flat rows returned by supabaseClient.js into the same nested
// event shape the UI components were built against (see buildEvents() in
// App.jsx for the reference shape). Keeping this mapping in one place means
// none of the existing components had to change to support a real backend —
// only the code that loads and saves data did.

export function assembleEventFromSupabase(eventRow, detail) {
  const assigneesByTask = {};
  for (const ta of detail.taskAssignees || []) {
    if (!assigneesByTask[ta.task_id]) assigneesByTask[ta.task_id] = [];
    assigneesByTask[ta.task_id].push(ta.planner_id);
  }

  const tasksByPhase = {};
  for (const t of detail.tasks) {
    if (!tasksByPhase[t.phase_id]) tasksByPhase[t.phase_id] = [];
    tasksByPhase[t.phase_id].push({
      id: t.id,
      label: t.label,
      done: t.done,
      assignee: t.assignee || null,
      visibility: t.visibility || "team",
      appointedPlannerIds: assigneesByTask[t.id] || [],
    });
  }

  const phases = [...detail.phases]
    .sort((a, b) => a.position - b.position)
    .map((p) => ({ id: p.id, title: p.title, tasks: tasksByPhase[p.id] || [] }));

  const team = detail.members.map((m) => {
    const label = m.planners?.display_name || m.planners?.email || "Unknown";
    return `${label} (${m.member_role === "lead" ? "Lead" : "Support"})`;
  });

  // Same roster as `team` above, but keeping the real planner id — `team`
  // is just display strings and can't be used to appoint someone to a
  // restricted task or resolve who "Jane (Lead)" actually refers to.
  const teamMembers = detail.members.map((m) => ({
    id: m.planner_id,
    name: m.planners?.display_name || m.planners?.email || "Unknown",
    role: m.member_role,
  }));

  const proposalItems = detail.proposalItems.map((pi) => ({
    id: pi.id, label: pi.label, qty: pi.qty, unitCost: pi.unit_cost,
  }));

  return {
    id: eventRow.id,
    name: eventRow.name,
    type: eventRow.type,
    clientName: eventRow.client_name || "",
    clientEmail: eventRow.client_email || "",
    date: eventRow.event_date || "TBD",
    venue: eventRow.venue || "TBD",
    status: eventRow.status,
    team,
    teamMembers,
    phases,
    budget: {
      total: eventRow.budget_total || 0,
      items: detail.budgetItems.map((b) => ({ label: b.label, planned: b.planned, actual: b.actual })),
    },
    proposal: detail.proposal
      ? {
          items: proposalItems,
          status: detail.proposal.status,
          sentAt: detail.proposal.sent_at,
          approvedAt: detail.proposal.approved_at,
          disapprovedAt: detail.proposal.disapproved_at,
        }
      : { items: proposalItems, status: "draft", sentAt: null, approvedAt: null, disapprovedAt: null },
    approvals: detail.approvals.map((a) => ({
      id: a.id, label: a.label, description: a.description,
      status: a.status, requestedAt: a.requested_at, approvedAt: a.approved_at, disapprovedAt: a.disapproved_at,
    })),
    vendors: detail.vendors.map((v) => ({
      id: v.id, name: v.name, category: v.category, contact: v.contact, phone: v.phone, cost: v.cost, deposit: v.deposit || 0, status: v.status,
    })),
    // 0025_client_payments.sql — money the client has sent the agency,
    // newest first (already ordered that way by the fetch).
    clientPayments: (detail.clientPayments || []).map((p) => ({
      id: p.id, amount: p.amount, dateSent: p.date_sent,
    })),
    messages: detail.messages.map((m) => ({
      id: m.id, authorType: m.author_type, authorName: m.author_name,
      body: m.body, imageData: m.image_url || undefined, timestamp: m.created_at,
    })),
    taskRequests: (detail.taskRequests || []).map((r) => ({
      id: r.id, label: r.label, description: r.description, status: r.status,
      requestedAt: r.requested_at, resolvedAt: r.resolved_at, resolvedTaskId: r.resolved_task_id,
    })),
  };
}
