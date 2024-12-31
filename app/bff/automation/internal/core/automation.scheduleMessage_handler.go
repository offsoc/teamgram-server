package automation

import (
    "time"
    "github.com/offsoc/teamgram-server/app/bff/automation/internal/core/rss"
    "github.com/offsoc/teamgram-server/app/bff/automation/internal/core/bots"
)

type ScheduleMessageHandler struct {
    botManager *bots.BotManager
    rssManager *rss.RSSManager
}

func NewScheduleMessageHandler(botManager *bots.BotManager, rssManager *rss.RSSManager) *ScheduleMessageHandler {
    return &ScheduleMessageHandler{
        botManager: botManager,
        rssManager: rssManager,
    }
}

func (h *ScheduleMessageHandler) ScheduleMessage(botID string, message string, scheduleTime time.Time) error {
    bot, err := h.botManager.GetBot(botID)
    if err != nil {
        return err
    }

    return bot.ScheduleMessage(message, scheduleTime)
}

func (h *ScheduleMessageHandler) ImportRSSFeed(botID string, feedURL string) error {
    bot, err := h.botManager.GetBot(botID)
    if err != nil {
        return err
    }

    feed, err := h.rssManager.FetchFeed(feedURL)
    if err != nil {
        return err
    }

    for _, item := range feed.Items {
        err := bot.ScheduleMessage(item.Content, item.PublishDate)
        if err != nil {
            return err
        }
    }

    return nil
}
