import { PgSelect, PgSelectQueryBuilder } from "drizzle-orm/pg-core";

import { sql } from "drizzle-orm";
import { db } from "@/db/init";
import { Context } from "hono";

export type PaginateResult<T> = {
  data: Array<T>;
  meta: {
    page: number;
    perPage: number;
    totalRecords: number;
    totalPages: number;
    nextPage?: number | null;
    prevPage?: number | null;
    url: {
      next?: string | null;
      prev: string | null;
    };
  };
};

export async function withPagination<T extends PgSelect>(
  c: Context,
  qb: T,
): Promise<PaginateResult<T>> {
  const query = new URLSearchParams(c.req.url);
  let page = Number(query.get("page"));
  let perPage = Number(query.get("perPage"));
  query.delete("page");
  query.delete("perPage");
  page = page || 1;
  perPage = perPage || 10;

  const offset = (Math.max(page, 1) - 1) * perPage;
  const subQuery = qb.as("sub_query");
  const [{ count: totalRecords }] = await db
    .select({
      count: sql<number>`count(*)`,
    })
    .from(subQuery);
  const data = await qb.offset(offset).limit(perPage);

  const totalPages = Math.ceil(totalRecords / perPage);
  const prevPage = page === 1 ? null : page - 1;
  const nextPage = page < totalPages ? page + 1 : null;
  const path = c.req.path;

  const nextUrl =
    nextPage === null
      ? null
      : createPaginatePath(
          {
            page: nextPage,
            perPage: perPage,
          },
          query,
          path,
        );

  const prevUrl =
    prevPage === null
      ? null
      : createPaginatePath(
          {
            page: prevPage,
            perPage,
          },
          query,
          path,
        );

  return {
    data: data as Array<T>,
    meta: {
      page,
      perPage,
      nextPage,
      prevPage,
      url: {
        prev: prevUrl,
        next: nextUrl,
      },
      totalRecords,
      totalPages,
    },
  };
}

function createPaginatePath(
  paginateQuery: { page: number; perPage: number },
  filterQuerys: URLSearchParams,
  path?: string,
) {
  const { page, perPage } = paginateQuery;
  const query = `page=${page}&perPage=${perPage}${filterQuerys.size > 1 ? "&" + filterQuerys.toString() : ""}`;

  return path ? `/${path}?${query}` : query;
}
