"use client";

import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PendingDocumentsTable } from "@/components/admin/pending-documents-table";
import {
  RefreshCw,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
} from "lucide-react";

interface StatusCounts {
  PENDING_REVIEW?: number;
  APPROVED?: number;
  REJECTED?: number;
  REVISION_REQUESTED?: number;
}

export default function AdminDocumentsPage() {
  const [documents, setDocuments] = useState<any[]>([]);
  const [statusCounts, setStatusCounts] = useState<StatusCounts>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const fetchDocuments = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      if (statusFilter !== "all") {
        params.set("status", statusFilter);
      }

      const response = await fetch(`/api/admin/documents?${params}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to fetch documents");
      }

      setDocuments(data.documents);
      setStatusCounts(data.statusCounts || {});
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchDocuments();
  }, [fetchDocuments]);

  const pendingCount = statusCounts.PENDING_REVIEW || 0;
  const approvedCount = statusCounts.APPROVED || 0;
  const rejectedCount = statusCounts.REJECTED || 0;
  const revisionCount = statusCounts.REVISION_REQUESTED || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">LP Documents</h1>
          <p className="text-muted-foreground">
            Review and manage documents uploaded by investors
          </p>
        </div>
        <Button variant="outline" onClick={fetchDocuments} disabled={loading}>
          <RefreshCw
            className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Review</CardTitle>
            <Clock className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{pendingCount}</div>
            <p className="text-xs text-muted-foreground">Awaiting your review</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Approved</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{approvedCount}</div>
            <p className="text-xs text-muted-foreground">Documents approved</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Revisions</CardTitle>
            <AlertCircle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{revisionCount}</div>
            <p className="text-xs text-muted-foreground">Awaiting LP updates</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Rejected</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rejectedCount}</div>
            <p className="text-xs text-muted-foreground">Documents rejected</p>
          </CardContent>
        </Card>
      </div>

      <Tabs
        defaultValue="pending"
        onValueChange={(v) =>
          setStatusFilter(v === "pending" ? "PENDING_REVIEW" : v === "all" ? "all" : v.toUpperCase())
        }
      >
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="pending" className="gap-2">
              <Clock className="h-4 w-4" />
              Pending {pendingCount > 0 && `(${pendingCount})`}
            </TabsTrigger>
            <TabsTrigger value="all">All Documents</TabsTrigger>
            <TabsTrigger value="approved">Approved</TabsTrigger>
            <TabsTrigger value="rejected">Rejected</TabsTrigger>
          </TabsList>
        </div>

        {error ? (
          <div className="flex items-center gap-2 p-4 mt-4 text-red-600 bg-red-50 rounded-lg">
            <AlertCircle className="h-4 w-4" />
            <span>{error}</span>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchDocuments}
              className="ml-auto"
            >
              Retry
            </Button>
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="mt-4">
            <PendingDocumentsTable
              documents={documents}
              onRefresh={fetchDocuments}
            />
          </div>
        )}
      </Tabs>
    </div>
  );
}
