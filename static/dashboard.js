// Dashboard JavaScript functionality
class PhishingDashboard {
  constructor() {
    this.apiBase = "/api"
    this.init()
  }

  async init() {
    await this.loadStats()
    await this.loadQuarantineData()
    await this.loadThreatTrends()

    // Refresh data every 30 seconds
    setInterval(() => {
      this.loadStats()
      this.loadQuarantineData()
    }, 30000)
  }

  async loadStats() {
    try {
      const response = await fetch(`${this.apiBase}/stats`)
      const stats = await response.json()

      document.getElementById("total-emails").textContent = stats.total_emails_analyzed
      document.getElementById("high-threats").textContent = stats.high_threat_emails
      document.getElementById("medium-threats").textContent = stats.medium_threat_emails
      document.getElementById("low-threats").textContent = stats.low_threat_emails
      document.getElementById("quarantined").textContent = stats.quarantined_emails

      this.updateRecentActivity(stats.recent_activity)
    } catch (error) {
      console.error("Failed to load stats:", error)
    }
  }

  updateRecentActivity(activities) {
    const container = document.getElementById("recent-activity")
    container.innerHTML = ""

    activities.slice(0, 5).forEach((activity) => {
      const item = document.createElement("div")
      item.className = "flex items-center justify-between p-3 bg-gray-50 rounded-lg"

      const threatColor = {
        HIGH: "text-red-600",
        MEDIUM: "text-yellow-600",
        LOW: "text-green-600",
      }[activity.threat_level]

      item.innerHTML = `
                <div class="flex-1">
                    <p class="text-sm font-medium text-gray-900">${activity.sender_email}</p>
                    <p class="text-xs text-gray-500">${activity.subject}</p>
                </div>
                <div class="text-right">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${threatColor} bg-opacity-10">
                        ${activity.threat_level}
                    </span>
                    <p class="text-xs text-gray-500 mt-1">${new Date(activity.analyzed_at).toLocaleTimeString()}</p>
                </div>
            `

      container.appendChild(item)
    })
  }

  async loadQuarantineData() {
    try {
      const response = await fetch(`${this.apiBase}/quarantine`)
      const emails = await response.json()

      const tbody = document.getElementById("quarantine-table")
      tbody.innerHTML = ""

      emails.forEach((email) => {
        const row = document.createElement("tr")
        row.className = "hover:bg-gray-50"

        const threatColor = {
          HIGH: "bg-red-100 text-red-800",
          MEDIUM: "bg-yellow-100 text-yellow-800",
          LOW: "bg-green-100 text-green-800",
        }[email.threat_level]

        row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${email.sender_email}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${email.subject}</td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${threatColor}">
                            ${email.threat_level}
                        </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${email.threat_score.toFixed(2)}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(email.quarantined_at).toLocaleString()}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button onclick="dashboard.releaseEmail('${email.email_id}')" 
                                class="text-blue-600 hover:text-blue-900 mr-3">Release</button>
                        <button onclick="dashboard.viewDetails('${email.email_id}')" 
                                class="text-gray-600 hover:text-gray-900">Details</button>
                    </td>
                `

        tbody.appendChild(row)
      })
    } catch (error) {
      console.error("Failed to load quarantine data:", error)
    }
  }

  async loadThreatTrends() {
    try {
      const response = await fetch(`${this.apiBase}/reports/threat-trends?days=7`)
      const data = await response.json()

      this.renderThreatTrendsChart(data.trends)
    } catch (error) {
      console.error("Failed to load threat trends:", error)
    }
  }

  renderThreatTrendsChart(trends) {
    const ctx = document.getElementById("threatTrendsChart").getContext("2d")

    const dates = Object.keys(trends).sort().slice(-7)
    const highData = dates.map((date) => trends[date]?.HIGH || 0)
    const mediumData = dates.map((date) => trends[date]?.MEDIUM || 0)
    const lowData = dates.map((date) => trends[date]?.LOW || 0)

    const Chart = window.Chart // Assuming Chart is globally available
    new Chart(ctx, {
      type: "line",
      data: {
        labels: dates.map((date) => new Date(date).toLocaleDateString()),
        datasets: [
          {
            label: "High Threats",
            data: highData,
            borderColor: "rgb(239, 68, 68)",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            tension: 0.1,
          },
          {
            label: "Medium Threats",
            data: mediumData,
            borderColor: "rgb(245, 158, 11)",
            backgroundColor: "rgba(245, 158, 11, 0.1)",
            tension: 0.1,
          },
          {
            label: "Low Threats",
            data: lowData,
            borderColor: "rgb(34, 197, 94)",
            backgroundColor: "rgba(34, 197, 94, 0.1)",
            tension: 0.1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "top",
          },
        },
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    })
  }

  async releaseEmail(emailId) {
    if (!confirm("Are you sure you want to release this email from quarantine?")) {
      return
    }

    try {
      const response = await fetch(`${this.apiBase}/quarantine/${emailId}/release`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.getAuthToken()}`,
        },
      })

      if (response.ok) {
        alert("Email released successfully")
        await this.loadQuarantineData()
        await this.loadStats()
      } else {
        alert("Failed to release email")
      }
    } catch (error) {
      console.error("Failed to release email:", error)
      alert("Failed to release email")
    }
  }

  viewDetails(emailId) {
    // TODO: Implement email details modal
    alert(`View details for email: ${emailId}`)
  }

  getAuthToken() {
    // TODO: Implement proper authentication
    return "dummy-token"
  }
}

// Initialize dashboard when page loads
const dashboard = new PhishingDashboard()
